#include "aktualizr-lite/tuf/tuf.h"

namespace aklite {
namespace tuf {
// TufRepoSource implementation for fetching local meta-dat
class LocalRepoSource : public RepoSource {
 public:
  class NotFoundException : public std::runtime_error {
   public:
    NotFoundException(const std::string& path) : std::runtime_error("Metadata hasn't been found; file path: " + path) {}
  };

  LocalRepoSource(std::string name_in, std::string local_path);
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
}  // namespace tuf
}  // namespace aklite
