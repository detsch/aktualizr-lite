#ifndef AKLITE_TUF_TUF_H_
#define AKLITE_TUF_TUF_H_

#include <iostream>
#include <string>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/property_tree/ptree.hpp>

#include "crypto/keymanager.h"
#include "http/httpclient.h"
#include "json/json.h"
#include "libaktualizr/config.h"
#include "storage/invstorage.h"
#include "uptane/fetcher.h"
#include "uptane/imagerepository.h"

#include "aktualizr-lite/tuf/tuf.h"

namespace Uptane {
class Target;
}

namespace aklite {
namespace tuf {

// enum class RoleEnum { Root = 0, Snapshot = 1, Targets = 2, Timestamp = 3, InvalidRole = -1 };
// virtual std::string fetchRole(RoleEnum role, int version) = 0;

// TODO: consider switching to a single fetchRole
class TufRepoSource {
 public:
  virtual std::string fetchRoot(int version) = 0;
  virtual std::string fetchTimestamp() = 0;
  virtual std::string fetchSnapshot() = 0;
  virtual std::string fetchTargets() = 0;
};

// TufRepoSource implementation for fetching remote meta-data via https using libaktualizr
class AkHttpsTufRepoSource : public TufRepoSource {
 public:
  AkHttpsTufRepoSource(std::string name_in, boost::property_tree::ptree& pt);
  ~AkHttpsTufRepoSource();

  virtual std::string fetchRoot(int version);
  virtual std::string fetchTimestamp();
  virtual std::string fetchSnapshot();
  virtual std::string fetchTargets();

 private:
  void init(std::string name_in, boost::property_tree::ptree& pt);
  void fillConfig(Config& config, boost::property_tree::ptree& pt);
  std::string fetchRole(Uptane::Role role, int64_t maxsize, Uptane::Version version);

  std::string name_;
  boost::filesystem::path tmp_dir_path_;
  std::shared_ptr<Uptane::IMetadataFetcher> meta_fetcher_;
};

// TufRepoSource implementation for fetching local meta-dat
class AkLocalTufRepoSource : public TufRepoSource {
 public:
  class NotFoundException : public std::runtime_error {
   public:
    NotFoundException(const std::string& path) : std::runtime_error("Metadata hasn't been found; file path: " + path) {}
  };

  AkLocalTufRepoSource(std::string name_in, boost::property_tree::ptree pt);
  AkLocalTufRepoSource(std::string uri);
  // DISCUSS: limit to max version?
  virtual std::string fetchRoot(int version);
  virtual std::string fetchTimestamp();
  virtual std::string fetchSnapshot();
  virtual std::string fetchTargets();

 private:
  virtual std::string fetchFile(boost::filesystem::path meta_file_path);

  std::string name;
  boost::filesystem::path src_dir_;
};

// Wrapper around any TufRepoSource implementation to make it usable directly by libaktualizr,
// by implementing Uptane::IMetadataFetcher interface
class FetcherWrapper : public Uptane::IMetadataFetcher {
 public:
  FetcherWrapper(std::shared_ptr<TufRepoSource> src);
  void fetchRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo, const Uptane::Role& role,
                 Uptane::Version version) const;

  void fetchLatestRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                       const Uptane::Role& role) const;

 private:
  std::shared_ptr<TufRepoSource> repo_src;
};

// Discuss: Keep custom as Json, or add explicit fields for the required values
struct Target {
 public:
  std::string filename;
  Json::Value custom;
  std::string uri;
  std::string hwid;
  std::string sha256_hash;
  std::string correlation_id;
  std::string type;
  uint64_t length;
  bool is_valid;

  // Temporarily keeping the original Uptane::Target, if available, facilitating gradual code migration
  Uptane::Target uptane_target;
};

class TufRepo {
 public:
  virtual std::vector<Target> GetTargets() = 0;
  virtual void updateMeta(std::shared_ptr<TufRepoSource> repo_src) = 0;
};

// TufRepo implementation that uses libaktualizr to provide TUF metadata handling and storage
class AkTufRepo : public TufRepo {
 public:
  AkTufRepo(boost::filesystem::path storage_path);
  AkTufRepo(const Config& config);
  virtual std::vector<Target> GetTargets();
  virtual void updateMeta(std::shared_ptr<TufRepoSource> repo_src);

 private:
  void init(boost::filesystem::path storage_path);

  Uptane::ImageRepository image_repo_;
  std::shared_ptr<INvStorage> storage_;
};

}  // namespace tuf
}  // namespace aklite

#endif