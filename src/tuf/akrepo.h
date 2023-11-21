#include "libaktualizr/config.h"
#include "storage/invstorage.h"
#include "uptane/fetcher.h"
#include "uptane/imagerepository.h"

#include "aktualizr-lite/tuf/tuf.h"
#include "target.h"

namespace aklite {
namespace tuf {

// TufRepo implementation that uses libaktualizr to provide TUF metadata handling and storage
class AkRepo : public TufRepo {
 public:
  AkRepo(boost::filesystem::path storage_path);
  AkRepo(const Config& config);
  virtual std::vector<TufTarget> GetTargets();
  virtual void updateMeta(std::shared_ptr<RepoSource> repo_src);
  virtual void checkMeta();

 private:
  void init(boost::filesystem::path storage_path);

  Uptane::ImageRepository image_repo_;
  std::shared_ptr<INvStorage> storage_;

  // Wrapper around any TufRepoSource implementation to make it usable directly by libaktualizr,
  // by implementing Uptane::IMetadataFetcher interface
  class FetcherWrapper : public Uptane::IMetadataFetcher {
   public:
    FetcherWrapper(std::shared_ptr<RepoSource> src);
    void fetchRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo, const Uptane::Role& role,
                   Uptane::Version version) const;

    void fetchLatestRole(std::string* result, int64_t maxsize, Uptane::RepositoryType repo,
                         const Uptane::Role& role) const;

   private:
    std::shared_ptr<RepoSource> repo_src;
  };
};

}  // namespace tuf
}  // namespace aklite
