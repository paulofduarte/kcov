/**
 * @file
 * @brief MachoParser backed by Zig's std.debug.Dwarf
 *
 * A replacement for parsers/macho-parser.cc that reads line tables from the
 * binary's .dSYM through the dwarf-zig bridge (dwarf_zig.h) instead of libdwarf.
 */
#include "dwarf_zig.h"

#include <capabilities.hh>
#include <configuration.hh>
#include <cstdlib>
#include <cstring>
#include <file-parser.hh>
#include <filter.hh>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <string>
#include <utils.hh>
#include <vector>

using namespace kcov;

namespace
{

void
reportLine(void* ctx, const char* file, size_t file_len, uint32_t line, uint64_t address)
{
    auto* listeners = static_cast<std::vector<IFileParser::ILineListener*>*>(ctx);
    std::string name(file, file_len);
    for (auto* listener : *listeners)
    {
        listener->onLine(name, line, address);
    }
}

class MachoParser : public IFileParser
{
public:
    MachoParser()
    {
        IParserManager::getInstance().registerParser(*this);
    }

private:
    bool addFile(const std::string& filename, struct phdr_data_entry* phdr_data) final
    {
        m_filename = filename;

        for (const auto l : m_fileListeners)
        {
            l->onFile(File(m_filename, IFileParser::FLG_NONE));
        }

        return true;
    }

    bool setMainFileRelocation(unsigned long relocation) final
    {
        return true;
    }

    uint64_t getChecksum() final
    {
        return 0;
    }

    void registerLineListener(ILineListener& listener) final
    {
        m_lineListeners.push_back(&listener);
    }

    void registerFileListener(IFileListener& listener) final
    {
        m_fileListeners.push_back(&listener);
    }

    bool parse() final
    {
        auto& conf = IConfiguration::getInstance();
        auto name = fmt("%s/%s.dSYM/Contents/Resources/DWARF/%s",
                        conf.keyAsString("binary-path").c_str(),
                        conf.keyAsString("binary-name").c_str(),
                        conf.keyAsString("binary-name").c_str());
        if (conf.keyAsInt("is-go-binary"))
        {
            name = fmt("%s/%s",
                       conf.keyAsString("binary-path").c_str(),
                       conf.keyAsString("binary-name").c_str());
        }

        dwarf_zig_for_each_line(name.c_str(), name.size(), reportLine, &m_lineListeners);

        return true;
    }

    std::string getParserType() final
    {
        return "Mach-O";
    }

    enum PossibleHits maxPossibleHits() final
    {
        return PossibleHits::HITS_LIMITED;
    }

    // Search for the "__go_buildinfo" section in the "__DATA" segment.
    bool isGoBinary(const std::string& filename)
    {
        size_t read_size = 0;
        auto full_file_content =
            static_cast<uint8_t*>(read_file(&read_size, "%s", filename.c_str()));
        auto hdr = reinterpret_cast<mach_header_64*>(full_file_content);
        auto cmd_ptr = full_file_content + sizeof(mach_header_64);
        for (auto i = 0; i < hdr->ncmds; i++)
        {
            auto cmd = reinterpret_cast<load_command*>(cmd_ptr);
            switch (cmd->cmd)
            {
            case LC_SEGMENT_64: {
                auto segment = reinterpret_cast<const struct segment_command_64*>(cmd_ptr);
                if (strcmp(segment->segname, "__DATA") == 0)
                {
                    auto section_ptr = cmd_ptr + sizeof(struct segment_command_64);
                    for (auto i = 0; i < segment->nsects; i++)
                    {
                        auto section = reinterpret_cast<struct section_64*>(section_ptr);
                        if (strcmp(section->sectname, "__go_buildinfo") == 0)
                        {
                            free((void*)full_file_content);
                            return true;
                        }
                        section_ptr += sizeof(*section);
                    }
                }
            }
            break;
            default:
                break;
            }
            cmd_ptr += cmd->cmdsize;
        }
        free((void*)full_file_content);
        return false;
    }

    unsigned int matchParser(const std::string& filename, uint8_t* data, size_t dataSize) final
    {
        auto hdr = reinterpret_cast<mach_header_64*>(data);

        // Don't handle big endian machines, or 32-bit binaries
        if (hdr->magic == FAT_MAGIC_64)
        {
            error("kcov doesn't support FAT binaries");
            return match_none;
        }
        if (hdr->magic == MH_MAGIC_64)
        {
            auto& conf = IConfiguration::getInstance();
            if (!conf.keyAsInt("is-go-binary") && isGoBinary(filename))
            {
                conf.setKey("is-go-binary", 1);
            }
            return match_perfect;
        }

        return match_none;
    }

    void setupParser(IFilter* filter) final
    {
        auto& conf = IConfiguration::getInstance();
        if (conf.keyAsInt("is-go-binary"))
        {
            // The Go linker puts DWARF in the binary instead of a separate dSYM file.
        }
        else
        {
            // Run dsymutil to make sure the DWARF info is available.
            auto dsymutil_command = fmt("dsymutil %s/%s",
                                        conf.keyAsString("binary-path").c_str(),
                                        conf.keyAsString("binary-name").c_str());
            kcov_debug(ELF_MSG, "running %s\n", dsymutil_command.c_str());

            system(dsymutil_command.c_str());
        }
    }

    std::vector<ILineListener*> m_lineListeners;
    std::vector<IFileListener*> m_fileListeners;
    std::string m_filename;
};

} // namespace

MachoParser g_machoParser;
