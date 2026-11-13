// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/readwritefile.h>

#include <logging.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

namespace {
FileReadStatus RegularFileStatus(const fs::path& filename, bool follow_symlinks = false)
{
    std::error_code ec;
    auto status = fs::symlink_status(filename, ec);
    if (status.type() == fs::file_type::not_found &&
        (!ec || ec == std::errc::no_such_file_or_directory)) {
        // A missing/unresolvable parent is an error, not permission to generate
        // a replacement identity through a dangling directory link.
        const auto parent = filename.parent_path().empty() ? fs::path{"."} : filename.parent_path();
        return fs::is_directory(parent, ec) && !ec ? FileReadStatus::NOT_FOUND : FileReadStatus::ERROR;
    }
    if (!ec && follow_symlinks && fs::is_symlink(status)) {
        status = fs::status(filename, ec);
    }
    // Dangling links must remain errors, even though status() reports not_found.
    if (ec || !fs::is_regular_file(status)) return FileReadStatus::ERROR;
    return FileReadStatus::OK;
}
} // namespace

FileReadResult ReadBinaryFileBounded(const fs::path& filename, size_t maxsize)
{
    const auto status = RegularFileStatus(filename, /*follow_symlinks=*/true);
    if (status != FileReadStatus::OK) return {status, {}};
    const auto close_file = [](FILE* file) { fclose(file); };
    std::unique_ptr<FILE, decltype(close_file)> file{fsbridge::fopen(filename, "rb"), close_file};
    if (!file) return {FileReadStatus::ERROR, {}};
    std::string data;
    char buffer[128];
    while (data.size() < maxsize) {
        const size_t n = fread(buffer, 1, std::min(sizeof(buffer), maxsize - data.size()), file.get());
        if (ferror(file.get())) return {FileReadStatus::ERROR, {}};
        data.append(buffer, n);
        if (feof(file.get())) break;
    }
    // Do not accept a valid prefix of an oversized identity (including maxsize=0).
    if (fgetc(file.get()) != EOF || ferror(file.get())) return {FileReadStatus::ERROR, {}};
    if (fclose(file.release()) != 0) return {FileReadStatus::ERROR, {}};
    return {FileReadStatus::OK, std::move(data)};
}

std::pair<bool,std::string> ReadBinaryFile(const fs::path &filename, size_t maxsize)
{
    FILE *f = fsbridge::fopen(filename, "rb");
    if (f == nullptr)
        return std::make_pair(false,"");
    std::string retval;
    char buffer[128];
    do {
        const size_t n = fread(buffer, 1, std::min(sizeof(buffer), maxsize - retval.size()), f);
        // Check for reading errors so we don't return any data if we couldn't
        // read the entire file (or up to maxsize)
        if (ferror(f)) {
            fclose(f);
            return std::make_pair(false,"");
        }
        retval.append(buffer, buffer+n);
    } while (!feof(f) && retval.size() < maxsize);
    fclose(f);
    return std::make_pair(true,retval);
}

bool WriteBinaryFile(const fs::path &filename, const std::string &data, bool commit)
{
    FILE *f = fsbridge::fopen(filename, "wb");
    if (f == nullptr)
        return false;
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) {
        fclose(f);
        return false;
    }
    if (commit && !FileCommit(f)) {
        fclose(f);
        return false;
    }
    if (fclose(f) != 0) {
        return false;
    }
    return true;
}

bool WriteBinaryFileAtomic(const fs::path& filename, const std::string& data)
{
    const auto status = RegularFileStatus(filename, /*follow_symlinks=*/true);
    if (status == FileReadStatus::ERROR) return false;
    fs::path destination{filename};
    if (status == FileReadStatus::OK) {
        std::error_code ec;
        destination = fs::canonical(filename, ec);
        if (ec) return false;
    }
    // Replace the resolved target, preserving any symlinks. The temporary must
    // be beside that target, including when the link crosses filesystems.
    const fs::path temporary{destination + ".tmp"};
    if (RegularFileStatus(temporary) == FileReadStatus::ERROR) return false;
    if (!WriteBinaryFile(temporary, data, /*commit=*/true)) return false;
    if (!RenameOver(temporary, destination)) return false;
    if (!DirectoryCommit(destination.parent_path().empty() ? fs::path{"."} : destination.parent_path())) {
        LogWarning("File %s was replaced, but its directory could not be synchronized; changes may not survive a system crash", fs::PathToString(destination));
    }
    return true;
}
