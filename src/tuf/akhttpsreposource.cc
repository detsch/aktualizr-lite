#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>

#include "crypto/keymanager.h"
#include "http/httpclient.h"
#include "storage/invstorage.h"
#include "uptane/imagerepository.h"

#include "akhttpsreposource.h"

namespace aklite {
namespace tuf {

AkHttpsRepoSource::AkHttpsRepoSource(std::string name_in, boost::property_tree::ptree& pt) {
  boost::program_options::variables_map m;
  Config config(m);
  fillConfig(config, pt);
  init(name_in, pt, config);
}

AkHttpsRepoSource::AkHttpsRepoSource(std::string name_in, boost::property_tree::ptree& pt, Config& config) {
  init(name_in, pt, config);
}

AkHttpsRepoSource::~AkHttpsRepoSource() {
  if (!tmp_dir_path_.empty()) {
    LOG_INFO << "Removing " << tmp_dir_path_;
    boost::filesystem::remove_all(tmp_dir_path_);
  }
}

void AkHttpsRepoSource::init(std::string name_in, boost::property_tree::ptree& pt, Config& config) {
  name_ = name_in;
  // Libaktualizr places certificate files inside a sqlite database
  tmp_dir_path_ = boost::filesystem::temp_directory_path() /
                  boost::filesystem::unique_path("aklite-tuf-\%\%\%\%-\%\%\%\%-\%\%\%\%-\%\%\%\%");
  boost::filesystem::create_directories(tmp_dir_path_);
  boost::filesystem::permissions(tmp_dir_path_, boost::filesystem::owner_all);
  LOG_INFO << "Created tmp dir: " << tmp_dir_path_;
  config.storage.path = tmp_dir_path_;

  auto storage = INvStorage::newStorage(config.storage, false, StorageClient::kTUF);
  storage->importData(config.import);

  auto key_manager = std_::make_unique<KeyManager>(storage, config.keymanagerConfig(), nullptr);
  key_manager->loadKeys();

  std::vector<std::string> headers;
  auto tag = Utils::stripQuotes(pt.get<std::string>("tag"));
  headers.emplace_back("x-ats-tags: " + tag);
  auto http_client = std::make_shared<HttpClientWithShare>(&headers);
  key_manager->copyCertsToCurl(*http_client);

  meta_fetcher_ = std::make_shared<Uptane::Fetcher>(config, http_client);
}

void AkHttpsRepoSource::fillConfig(Config& config, boost::property_tree::ptree& pt) {
  bool enable_hsm = pt.count("p11_module") > 0;
  if (enable_hsm) {
    config.p11.module = Utils::stripQuotes(pt.get<std::string>("p11_module"));
    config.p11.pass = Utils::stripQuotes(pt.get<std::string>("pass"));
  }

  if (enable_hsm && pt.count("tls_pkey_id") > 0) {
    config.tls.pkey_source = CryptoSource::kPkcs11;
    config.p11.tls_pkey_id = Utils::stripQuotes(pt.get<std::string>("tls_pkey_id"));
  } else {
    config.tls.pkey_source = CryptoSource::kFile;
    config.import.tls_pkey_path = utils::BasedPath(Utils::stripQuotes(pt.get<std::string>("tls_pkey_path")));
  }

  if (enable_hsm && pt.count("tls_cacert_id") > 0) {
    config.tls.ca_source = CryptoSource::kPkcs11;
    config.p11.tls_pkey_id = Utils::stripQuotes(pt.get<std::string>("tls_cacert_id"));
  } else {
    config.tls.ca_source = CryptoSource::kFile;
    config.import.tls_cacert_path = utils::BasedPath(Utils::stripQuotes(pt.get<std::string>("tls_cacert_path")));
  }

  if (enable_hsm && pt.count("tls_clientcert_id") > 0) {
    config.tls.cert_source = CryptoSource::kPkcs11;
    config.p11.tls_pkey_id = Utils::stripQuotes(pt.get<std::string>("tls_clientcert_id"));
  } else {
    config.tls.cert_source = CryptoSource::kFile;
    config.import.tls_clientcert_path =
        utils::BasedPath(Utils::stripQuotes(pt.get<std::string>("tls_clientcert_path")));
  }

  config.uptane.repo_server = Utils::stripQuotes(pt.get<std::string>("uri"));
}

std::string AkHttpsRepoSource::fetchRole(Uptane::Role role, int64_t maxsize, Uptane::Version version) {
  std::cout << "fetchRole(HTTP) " << role << std::endl;
  std::string reply;
  meta_fetcher_->fetchRole(&reply, maxsize, Uptane::RepositoryType::Image(), role, version);
  return reply;
}

std::string AkHttpsRepoSource::fetchRoot(int version) {
  return fetchRole(Uptane::Role::Root(), Uptane::kMaxRootSize, Uptane::Version(version));
}

std::string AkHttpsRepoSource::fetchTimestamp() {
  return fetchRole(Uptane::Role::Timestamp(), Uptane::kMaxTimestampSize, Uptane::Version());
}

std::string AkHttpsRepoSource::fetchSnapshot() {
  return fetchRole(Uptane::Role::Snapshot(), Uptane::kMaxSnapshotSize, Uptane::Version());
}

std::string AkHttpsRepoSource::fetchTargets() {
  return fetchRole(Uptane::Role::Targets(), Uptane::kMaxImageTargetsSize, Uptane::Version());
}

}  // namespace tuf
}  // namespace aklite
