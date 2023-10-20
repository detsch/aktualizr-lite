#include "aktualizr-lite/tuf/tuf.h"

namespace aklite {
namespace tuf {

AkHttpsTufRepoSource::AkHttpsTufRepoSource(std::string name_in, boost::property_tree::ptree& pt) { init(name_in, pt); }

AkHttpsTufRepoSource::~AkHttpsTufRepoSource() {
  if (!tmp_dir_path_.empty()) {
    LOG_INFO << "Removing " << tmp_dir_path_;
    boost::filesystem::remove_all(tmp_dir_path_);
  }
}

void AkHttpsTufRepoSource::init(std::string name_in, boost::property_tree::ptree& pt) {
  name_ = name_in;

  boost::program_options::variables_map m;
  Config config(m);
  fillConfig(config, pt);

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

void AkHttpsTufRepoSource::fillConfig(Config& config, boost::property_tree::ptree& pt) {
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

std::string AkHttpsTufRepoSource::fetchRole(Uptane::Role role, int64_t maxsize, Uptane::Version version) {
  std::cout << "fetchRole(HTTP) " << role << std::endl;
  std::string reply;
  meta_fetcher_->fetchRole(&reply, maxsize, Uptane::RepositoryType::Image(), role, version);
  return reply;
}

std::string AkHttpsTufRepoSource::fetchRoot(int version) {
  return fetchRole(Uptane::Role::Root(), Uptane::kMaxRootSize, Uptane::Version(version));
}

std::string AkHttpsTufRepoSource::fetchTimestamp() {
  return fetchRole(Uptane::Role::Timestamp(), Uptane::kMaxTimestampSize, Uptane::Version());
}

std::string AkHttpsTufRepoSource::fetchSnapshot() {
  return fetchRole(Uptane::Role::Snapshot(), Uptane::kMaxSnapshotSize, Uptane::Version());
}

std::string AkHttpsTufRepoSource::fetchTargets() {
  return fetchRole(Uptane::Role::Targets(), Uptane::kMaxImageTargetsSize, Uptane::Version());
}

// AkLocalTufRepoSource
std::string AkLocalTufRepoSource::fetchFile(boost::filesystem::path meta_file_path) {
  std::cout << "fetchFile " << meta_file_path << std::endl;
  if (!boost::filesystem::exists(meta_file_path)) throw NotFoundException(meta_file_path.string());

  return Utils::readFile(meta_file_path);
}

AkLocalTufRepoSource::AkLocalTufRepoSource(std::string name_in, boost::property_tree::ptree pt) {
  name = name_in;
  auto uri = Utils::stripQuotes(pt.get<std::string>("uri"));
  if (uri.rfind("file://", 0) == 0) {
    uri = uri.erase(0, strlen("file://"));
  }
  src_dir_ = boost::filesystem::path(uri);
}

AkLocalTufRepoSource::AkLocalTufRepoSource(std::string uri) { src_dir_ = boost::filesystem::path(uri); }

// DISCUSS: limit to max version?
std::string AkLocalTufRepoSource::fetchRoot(int version) {
  return fetchFile(src_dir_ / (std::to_string(version) + ".root.json"));
}

std::string AkLocalTufRepoSource::fetchTimestamp() { return fetchFile(src_dir_ / "timestamp.json"); }

std::string AkLocalTufRepoSource::fetchSnapshot() { return fetchFile(src_dir_ / "snapshot.json"); }

std::string AkLocalTufRepoSource::fetchTargets() { return fetchFile(src_dir_ / "targets.json"); }

// FetcherWrapper
FetcherWrapper::FetcherWrapper(std::shared_ptr<TufRepoSource> src) { repo_src = src; }
void FetcherWrapper::fetchRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                               const Uptane::Role& role, Uptane::Version version) const {
  std::string json;
  if (role == Uptane::Role::Root())
    json = repo_src->fetchRoot(version.version());
  else if (role == Uptane::Role::Timestamp())
    json = repo_src->fetchTimestamp();
  else if (role == Uptane::Role::Snapshot())
    json = repo_src->fetchSnapshot();
  else if (role == Uptane::Role::Targets())
    json = repo_src->fetchTargets();
  else
    throw std::runtime_error("Invalid TUF Role " + role.ToString());

  *result = json;
}

void FetcherWrapper::fetchLatestRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                                     const Uptane::Role& role) const {
  fetchRole(result, maxsize, repo, role, Uptane::Version());
}

// AkTufRepo
AkTufRepo::AkTufRepo(boost::filesystem::path storage_path) { init(storage_path); }

AkTufRepo::AkTufRepo(const Config& config) {
  storage_ = INvStorage::newStorage(config.storage, false, StorageClient::kTUF);
  storage_->importData(config.import);
}

std::vector<Target> AkTufRepo::GetTargets() {
  std::shared_ptr<const Uptane::Targets> targets{image_repo_.getTargets()};
  if (targets) {
    auto ret = std::vector<Target>();
    for (const auto& up_target : image_repo_.getTargets()->targets) {
      Target target{
          .filename = up_target.filename(),
          .custom = up_target.custom_data(),
          .uri = up_target.uri(),
          .hwid = up_target.hardwareIds().at(0).ToString(),
          .sha256_hash = up_target.sha256Hash(),
          .correlation_id = up_target.correlation_id(),
          .type = up_target.type(),
          .length = up_target.length(),
          .is_valid = up_target.IsValid(),
          .uptane_target = up_target,
      };
      ret.emplace_back(target);
    }
    return ret;
  } else {
    return std::vector<Target>();
  }
}

void AkTufRepo::updateMeta(std::shared_ptr<TufRepoSource> repo_src) {
  FetcherWrapper wrapper(repo_src);
  image_repo_.updateMeta(*storage_, wrapper);
}

void AkTufRepo::init(boost::filesystem::path storage_path) {
  StorageConfig sc;
  sc.path = storage_path;
  storage_ = INvStorage::newStorage(sc, false, StorageClient::kTUF);
}

}  // namespace tuf
}  // namespace aklite
