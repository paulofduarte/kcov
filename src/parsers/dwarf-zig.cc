/**
 * @file
 * @brief DwarfParser backed by Zig's std.debug.Dwarf
 *
 * A drop-in replacement for parsers/dwarf.cc that reads line tables through the
 * dwarf-zig bridge (dwarf_zig.h) instead of libdw, so DWARF emitted by Zig's
 * self-hosted backend is read correctly.
 */
#include "dwarf.hh"
#include "dwarf_zig.h"

#include <string>
#include <sys/stat.h>

using namespace kcov;

namespace
{

void
reportLine(void* ctx, const char* file, size_t file_len, uint32_t line, uint64_t address)
{
    auto* listener = static_cast<IFileParser::ILineListener*>(ctx);
    listener->onLine(std::string(file, file_len), line, address);
}

struct AddressFilter
{
    IFileParser::ILineListener* listener;
    uint64_t address;
};

void
reportAddress(void* ctx, const char* file, size_t file_len, uint32_t line, uint64_t address)
{
    auto* filter = static_cast<AddressFilter*>(ctx);
    if (address == filter->address)
        filter->listener->onLine(std::string(file, file_len), line, address);
}

} // namespace

class DwarfParser::Impl
{
public:
    std::string m_filename;
};

DwarfParser::DwarfParser()
{
    m_impl = new DwarfParser::Impl();
}

DwarfParser::~DwarfParser()
{
    close();
    delete m_impl;
}

bool
DwarfParser::open(const std::string& filename)
{
    struct stat st;
    if (stat(filename.c_str(), &st) != 0)
        return false;

    m_impl->m_filename = filename;
    return true;
}

void
DwarfParser::forEachLine(IFileParser::ILineListener& listener)
{
    if (m_impl->m_filename.empty())
        return;

    dwarf_zig_for_each_line(
        m_impl->m_filename.c_str(), m_impl->m_filename.size(), reportLine, &listener);
}

void
DwarfParser::forAddress(IFileParser::ILineListener& listener, uint64_t address)
{
    if (m_impl->m_filename.empty())
        return;

    AddressFilter filter = {&listener, address};
    dwarf_zig_for_each_line(
        m_impl->m_filename.c_str(), m_impl->m_filename.size(), reportAddress, &filter);
}

void
DwarfParser::close()
{
    m_impl->m_filename.clear();
}
