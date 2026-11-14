// Copyright (c) 2015-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_READWRITEFILE_H
#define BITCOIN_UTIL_READWRITEFILE_H

#include <util/fs.h>

#include <limits>
#include <string>
#include <utility>

/** Read full contents of a file and return them in a std::string.
 * Returns a pair <status, string>.
 * If an error occurred, status will be false, otherwise status will be true and the data will be returned in string.
 *
 * @param maxsize Puts a maximum size limit on the file that is read. If the file is larger than this, truncated data
 *         (with len > maxsize) will be returned.
 */
std::pair<bool,std::string> ReadBinaryFile(const fs::path &filename, size_t maxsize=std::numeric_limits<size_t>::max());

enum class FileReadStatus { OK, NOT_FOUND, FAILED };
struct FileReadResult {
    FileReadStatus status;
    std::string data;
};

/** Read an entire regular file, following symlinks and rejecting excess bytes and special files.
 * NOT_FOUND means the path is absent, not an unreadable or dangling symlink.
 * Assumes the datadir is trusted: the type check is not resistant to concurrent
 * replacement of paths by another process. FAILED never returns partial data.
 */
FileReadResult ReadBinaryFileBounded(const fs::path& filename, size_t maxsize);

/** Write contents of std::string to a file.
 * @param commit Synchronize file contents before closing; does not synchronize its directory.
 * @return true on success.
 */
bool WriteBinaryFile(const fs::path &filename, const std::string &data, bool commit = false);

/** Save through a sibling .tmp file, checking write, file commit, close and rename.
 * Existing destination symlinks are resolved and preserved; the temporary is
 * beside the resolved regular-file target and must not itself be a symlink.
 * Dangling links and special files are errors. Callers must serialize writes
 * and trust the datadir (concurrent path replacement is not defended against).
 * Failure before rename preserves the destination. After rename, directory sync
 * is best effort: failure is logged as a warning, not returned as a failed save.
 * Directory synchronization is supported on POSIX only; see DirectoryCommit().
 */
bool WriteBinaryFileAtomic(const fs::path& filename, const std::string& data);

#endif // BITCOIN_UTIL_READWRITEFILE_H
