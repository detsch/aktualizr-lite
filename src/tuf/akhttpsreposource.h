#include "uptane/fetcher.h"

#include "aktualizr-lite/tuf/tuf.h"

namespace aklite {
namespace tuf {

// TufRepoSource implementation for fetching remote meta-data via https using libaktualizr
class AkHttpsRepoSource : public RepoSource {
 public:
  AkHttpsRepoSource(std::string name_in, boost::property_tree::ptree& pt);
  AkHttpsRepoSource(std::string name_in, boost::property_tree::ptree& pt, Config& config);
  ~AkHttpsRepoSource();

  virtual std::string fetchRoot(int version);
  virtual std::string fetchTimestamp();
  virtual std::string fetchSnapshot();
  virtual std::string fetchTargets();

 private:
  void init(std::string name_in, boost::property_tree::ptree& pt, Config& config);
  void fillConfig(Config& config, boost::property_tree::ptree& pt);
  std::string fetchRole(Uptane::Role role, int64_t maxsize, Uptane::Version version);

  std::string name_;
  boost::filesystem::path tmp_dir_path_;
  std::shared_ptr<Uptane::IMetadataFetcher> meta_fetcher_;
};

}  // namespace tuf
}  // namespace aklite