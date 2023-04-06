#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/algorithm/string.hpp>
#include <boost/process.hpp>

#include "test_utils.h"
#include "uptane_generator/image_repo.h"

#include "appengine.h"
#include "composeappmanager.h"
#include "liteclient.h"
#include "target.h"

#include "fixtures/liteclienttest.cc"

using ::testing::NiceMock;
using ::testing::Return;

/**
 * Class MockAppEngine
 *
 */
class MockAppEngine : public AppEngine {
 public:
  MockAppEngine(bool default_behaviour = true) {
    if (!default_behaviour) return;

    ON_CALL(*this, fetch).WillByDefault(Return(true));
    ON_CALL(*this, verify).WillByDefault(Return(true));
    ON_CALL(*this, install).WillByDefault(Return(true));
    ON_CALL(*this, run).WillByDefault(Return(true));
    ON_CALL(*this, isFetched).WillByDefault(Return(true));
    ON_CALL(*this, isRunning).WillByDefault(Return(true));
    ON_CALL(*this, getRunningAppsInfo)
        .WillByDefault(
            Return(Utils::parseJSON("{\"app-07\": {\"services\": {\"nginx-07\": {\"hash\": "
                                    "\"16e36b4ab48cb19c7100a22686f85ffcbdce5694c936bda03cb12a2cce88efcf\"}}}}")));
  }

 public:
  MOCK_METHOD(AppEngine::Result, fetch, (const App& app), (override));
  MOCK_METHOD(AppEngine::Result, verify, (const App& app), (override));
  MOCK_METHOD(AppEngine::Result, install, (const App& app), (override));
  MOCK_METHOD(AppEngine::Result, run, (const App& app), (override));
  MOCK_METHOD(void, stop, (const App& app), (override));
  MOCK_METHOD(void, remove, (const App& app), (override));
  MOCK_METHOD(bool, isFetched, (const App& app), (const, override));
  MOCK_METHOD(bool, isRunning, (const App& app), (const, override));
  MOCK_METHOD(AppEngine::Apps, getInstalledApps, (), (const, override));
  MOCK_METHOD(Json::Value, getRunningAppsInfo, (), (const, override));
  MOCK_METHOD(void, prune, (const Apps& app), (override));
};

class BootFlagMgmtTest : public fixtures::ClientTest {
 protected:
  std::shared_ptr<LiteClient> createLiteClient(InitialVersion initial_version = InitialVersion::kOn,
                                               boost::optional<std::vector<std::string>> apps = boost::none,
                                               bool finalize = true) override {
    app_engine_mock_ = std::make_shared<NiceMock<MockAppEngine>>();

    auto client =
        ClientTest::createLiteClient(app_engine_mock_, initial_version, apps, "", boost::none, true, finalize);
    boot_flag_mgr_->set("rollback_protection");
    return client;
  }

  std::shared_ptr<NiceMock<MockAppEngine>>& getAppEngine() { return app_engine_mock_; }
  RollbackMode bootloader_type_{RollbackMode::kBootloaderNone};

 private:
  std::shared_ptr<NiceMock<MockAppEngine>> app_engine_mock_;
};

class BootFlagMgmtTestSuite : public BootFlagMgmtTest,
                              public ::testing::WithParamInterface<std::tuple<std::string, RollbackMode>> {
 protected:
  void tweakConf(Config& conf) override {
    std::string pacman_type;
    RollbackMode bootloader_mode;

    std::tie(pacman_type, bootloader_mode) = GetParam();
    conf.pacman.type = pacman_type;
    conf.bootloader.rollback_mode = bootloader_mode;
    conf.pacman.extra["ostree_update_block"] = "1";
    bootloader_type_ = bootloader_mode;
  };
};

TEST_P(BootFlagMgmtTestSuite, OstreeUpdate) {
  // boot device
  auto client = createLiteClient();
  ASSERT_TRUE(targetsMatch(client->getCurrent(), getInitialTarget()));

  // Create a new Target: update rootfs and commit it into Treehub's repo
  auto new_target = createTarget();
  update(*client, getInitialTarget(), new_target);
  if (bootloader_type_ != RollbackMode::kUbootGeneric) {
    ASSERT_EQ(boot_flag_mgr_->get("bootupgrade_available"), 1);
    ASSERT_TRUE(client->isBootFwUpdateInProgress());
  }

  // reboot device, and don't reset the boot upgrade flag to emulate the bootloader A/B update
  reboot(client, boost::none, false);
  ASSERT_TRUE(targetsMatch(client->getCurrent(), new_target));
  checkHeaders(*client, new_target);
  if (bootloader_type_ == RollbackMode::kUbootGeneric) {
    return;
  }

  // boot fw udpate is in progress
  ASSERT_TRUE(client->isBootFwUpdateInProgress());
  // make sure update is banned until a device is rebooted
  auto new_target_01 = createTarget();
  update(*client, new_target, new_target_01);
  // verify that the new target `new_target_01` was not actually applied and is not pending
  ASSERT_FALSE(client->isPendingTarget(new_target_01));

  // now, do reboot to confirm the boot fw update
  reboot(client);
  // and try the update again
  update(*client, new_target, new_target_01);
  reboot(client);
  ASSERT_TRUE(targetsMatch(client->getCurrent(), new_target_01));
  ASSERT_EQ(boot_flag_mgr_->get("bootupgrade_available"), 0);
  ASSERT_FALSE(client->isBootFwUpdateInProgress());
}

TEST_P(BootFlagMgmtTestSuite, OstreeUpdateIfBootloaderRollbacks) {
  // boot device
  auto client = createLiteClient();
  ASSERT_TRUE(targetsMatch(client->getCurrent(), getInitialTarget()));
  // Create a new Target: update rootfs and commit it into Treehub's repo
  auto new_target = createTarget(nullptr, "", "", boost::none, "", "bootfirmware_version=0");
  // Boot firmware update is not expected because the new target's version is lower (0) than the current one (1)
  update(*client, getInitialTarget(), new_target,
         bootloader_type_ == RollbackMode::kUbootGeneric ? data::ResultCode::Numeric::kNeedCompletion
                                                         : data::ResultCode::Numeric::kInstallFailed,
         {DownloadResult::Status::Ok, ""}, "", false);
  ASSERT_EQ(boot_flag_mgr_->get("bootupgrade_available"), 0);
  ASSERT_FALSE(client->isBootFwUpdateInProgress());
  if (bootloader_type_ != RollbackMode::kUbootGeneric) {
    ASSERT_TRUE(client->isRollback(new_target));
  } else {
    ASSERT_FALSE(client->isRollback(new_target));
  }

  reboot(client);
  if (bootloader_type_ == RollbackMode::kUbootGeneric) {
    // installation should be successfull for the generic bootloader since it doesn't support
    // update and there is no "bootloader rollback".
    ASSERT_TRUE(targetsMatch(client->getCurrent(), new_target));
    checkHeaders(*client, new_target);
  } else {
    ASSERT_TRUE(targetsMatch(client->getCurrent(), getInitialTarget()));
  }
}

INSTANTIATE_TEST_SUITE_P(
    BootFlagMgmtTestSuiteParam, BootFlagMgmtTestSuite,
    ::testing::Values(std::tuple<std::string, RollbackMode>{"ostree", RollbackMode::kUbootGeneric},
                      std::tuple<std::string, RollbackMode>{"ostree", RollbackMode::kUbootMasked},
                      std::tuple<std::string, RollbackMode>{"ostree", RollbackMode::kFioVB},
                      std::tuple<std::string, RollbackMode>{"ostree+compose_apps", RollbackMode::kUbootGeneric},
                      std::tuple<std::string, RollbackMode>{"ostree+compose_apps", RollbackMode::kUbootMasked},
                      std::tuple<std::string, RollbackMode>{"ostree+compose_apps", RollbackMode::kFioVB}));

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << argv[0] << " invalid arguments\n";
    return EXIT_FAILURE;
  }

  ::testing::InitGoogleTest(&argc, argv);
  logger_init();

  // options passed as args in CMakeLists.txt
  fixtures::DeviceGatewayMock::RunCmd = argv[1];
  fixtures::SysRootFS::CreateCmd = argv[2];
  return RUN_ALL_TESTS();
}
