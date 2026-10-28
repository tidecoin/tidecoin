// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FS_HELPERS_H
#define BITCOIN_UTIL_FS_HELPERS_H

#include <util/fs.h>

#include <cstdint>
#include <cstdio>
#include <iosfwd>
#include <limits>
#include <optional>

#ifndef WIN32
#include <sys/types.h>
#endif

#ifdef __APPLE__
enum class FSType {
    EXFAT,
    OTHER,
    ERROR
};

/**
 * Detect filesystem type for a given path.
 * Currently identifies exFAT filesystems which cause issues on macOS.
 *
 * @param[in] path The directory path to check
 * @return FSType enum indicating the filesystem type
 */
FSType GetFilesystemType(const fs::path& path);
#endif

/**
 * Ensure file contents are fully committed to disk, using a platform-specific
 * feature analogous to fsync().
 */
bool FileCommit(FILE* file);

/**
 * Sync directory contents. This is required on some environments to ensure that
 * newly created files are committed to disk.
 */
void DirectoryCommit(const fs::path& dirname);

bool TruncateFile(FILE* file, uint64_t length);

/** File positioning with 64-bit offsets, including Windows and 32-bit Unix. */
inline int FileSeek64(FILE* file, int64_t offset, int origin)
{
#if defined(WIN32)
    return _fseeki64(file, offset, origin);
#else
    static_assert(sizeof(off_t) >= sizeof(int64_t), "64-bit file offsets required");
    return fseeko(file, offset, origin);
#endif
}

inline int64_t FileTell64(FILE* file)
{
#if defined(WIN32)
    return _ftelli64(file);
#else
    static_assert(sizeof(off_t) >= sizeof(int64_t), "64-bit file offsets required");
    return ftello(file);
#endif
}

/** Try to raise the descriptor limit to min_fd (nonnegative), without exceeding
 * the hard limit. Return the available limit, saturated at INT_MAX, including
 * infinity. If the initial query fails, return min_fd; Windows returns 2048. */
int RaiseFileDescriptorLimit(int min_fd);
void AllocateFileRange(FILE* file, uint64_t offset, unsigned int length);

/**
 * Rename src to dest.
 * @return true if the rename was successful.
 */
[[nodiscard]] bool RenameOver(fs::path src, fs::path dest);

namespace util {
enum class LockResult {
    Success,
    ErrorWrite,
    ErrorLock,
};
[[nodiscard]] LockResult LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only = false);
} // namespace util
void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name);
bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes = 0);

/** Get the size of a file by scanning it.
 *
 * @param[in] path The file path
 * @param[in] max Stop seeking beyond this limit
 * @return The file size or max
 */
std::streampos GetFileSize(const char* path, std::streamsize max = std::numeric_limits<std::streamsize>::max());

/** Release all directory locks. This is used for unit testing only, at runtime
 * the global destructor will take care of the locks.
 */
void ReleaseDirectoryLocks();

bool TryCreateDirectories(const fs::path& p);

/** Probe directory writability by creating and removing a temporary file. */
bool IsDirWritable(const fs::path& path);
fs::path GetDefaultDataDir();

/** Convert fs::perms to symbolic string of the form 'rwxrwxrwx'
 *
 * @param[in] p the perms to be converted
 * @return Symbolic permissions string
 */
std::string PermsToSymbolicString(fs::perms p);
/** Interpret a custom permissions level string as fs::perms
 *
 * @param[in] s Permission level string
 * @return Permissions as fs::perms
 */
std::optional<fs::perms> InterpretPermString(const std::string& s);

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif // BITCOIN_UTIL_FS_HELPERS_H
