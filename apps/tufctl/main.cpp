#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include "aktualizr-lite/tuf/tuf.h"

// Strip leading and trailing quotes
std::string strip_quotes(const std::string& value) {
  std::string res = value;
  res.erase(std::remove(res.begin(), res.end(), '\"'), res.end());
  return res;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "Usage example: " << argv[0] << " repo_sources.toml" << std::endl;
    exit(1);
  }

  boost::filesystem::path storage_path;

  std::vector<std::shared_ptr<aklite::tuf::TufRepoSource>> sources;
  // Set up
  {
    boost::property_tree::ptree pt;
    boost::property_tree::ini_parser::read_ini(argv[1], pt);

    std::ostringstream oss;
    boost::property_tree::write_json(oss, pt);
    std::cout << oss.str();

    for (boost::property_tree::ptree::iterator pos = pt.begin(); pos != pt.end();) {
      std::cout << pos->first << std::endl;

      if (pos->first.rfind("source ") == 0) {
        std::cout << "got repo " << pos->first.substr(7) << std::endl;
        std::string uri = pos->second.get<std::string>("uri");
        std::cout << "uri " << uri << " " << uri.rfind("\"file://", 0) << std::endl;

        std::shared_ptr<aklite::tuf::TufRepoSource> source;
        if (uri.rfind("\"file://", 0) == 0) {
          source = std::make_shared<aklite::tuf::AkLocalTufRepoSource>(pos->first, pos->second);
        } else {
          source = std::make_shared<aklite::tuf::AkHttpsTufRepoSource>(pos->first, pos->second);
        }
        sources.push_back(source);
      }

      if (pos->first == "storage") {
        storage_path = strip_quotes(pos->second.get<std::string>("path"));
      }

      ++pos;
    }
  }

  // Try individual fetch operations. sota.toml is not used
  {
    for (auto const& source : sources) {
      Json::StreamWriterBuilder builder;
      builder["indentation"] = "  ";
      try {
        auto json = source->fetchRoot(1);
        std::cout << json << std::endl;
      } catch (std::runtime_error e) {
        std::cout << e.what() << std::endl;
      }
      try {
        auto json = source->fetchTimestamp();
        std::cout << json << std::endl;
      } catch (std::runtime_error e) {
        std::cout << e.what() << std::endl;
      }

      try {
        auto json = source->fetchSnapshot();
        std::cout << json << std::endl;
      } catch (std::runtime_error e) {
        std::cout << e.what() << std::endl;
      }
      try {
        auto json = source->fetchTargets();
        // std::cout << json << std::endl;
      } catch (std::runtime_error e) {
        std::cout << e.what() << std::endl;
      }
    }
  }

  // Perform TUF refresh for each repo source, using libaktualizr implementation of TufRepo
  {
    aklite::tuf::AkTufRepo repo(storage_path);
    for (auto const& source : sources) {
      repo.updateMeta(source);
    }

    auto targets = repo.GetTargets();
    for (auto const& target : targets) {
      std::cout << target.filename << " " << target.uri << std::endl;
    }
  }
}
