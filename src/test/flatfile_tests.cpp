// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <clientversion.h>
#include <chain.h>
#include <compat/compat.h>
#include <common/args.h>
#include <flatfile.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs_helpers.h>

#ifdef WIN32
#include <io.h>
#include <winioctl.h>
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(flatfile_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(flatfile_large_position_serialization)
{
    for (const uint64_t offset : {uint64_t{123}, (uint64_t{1} << 31) + 7, (uint64_t{1} << 32) + 7}) {
        FlatFilePos original{3, offset}, restored;
        DataStream stream;
        stream << original;
        if (offset <= UINT32_MAX) {
            // Existing positions retain their exact encoding.
            DataStream old;
            int file{3};
            uint32_t pos = offset;
            old << VARINT_MODE(file, VarIntMode::NONNEGATIVE_SIGNED) << VARINT(pos);
            BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), old.begin(), old.end());
        }
        stream >> restored;
        BOOST_CHECK_EQUAL(restored.nFile, original.nFile);
        BOOST_CHECK_EQUAL(restored.nPos, offset);

        CBlockFileInfo info, restored_info;
        info.nSize = offset;
        info.nUndoSize = offset + 1;
        stream << info;
        stream >> restored_info;
        BOOST_CHECK_EQUAL(restored_info.nSize, offset);
        BOOST_CHECK_EQUAL(restored_info.nUndoSize, offset + 1);

        CDiskBlockIndex index, restored_index;
        {
            LOCK(cs_main);
            index.nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
            index.nDataPos = offset;
            index.nUndoPos = offset + 1;
        }
        stream << index;
        stream >> restored_index;
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(restored_index.nDataPos, offset);
        BOOST_CHECK_EQUAL(restored_index.nUndoPos, offset + 1);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_large_offsets)
{
    FlatFileSeq seq{m_args.GetDataDirBase(), "large", 16 * 1024};
    {
        FILE* raw_file{seq.Open({0, 0})};
        AutoFile file{raw_file};
        BOOST_REQUIRE(!file.IsNull());
#ifdef WIN32
        // Avoid allocating gigabytes for holes on Windows filesystems.
        DWORD returned{0};
        if (!DeviceIoControl(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(raw_file))),
                             FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr)) {
            BOOST_TEST_MESSAGE("Skipping large-offset file test: filesystem does not support sparse files");
            return;
        }
#endif
        file << uint8_t{42};
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    for (const uint64_t offset : {(uint64_t{1} << 31) + 7, (uint64_t{1} << 32) + 7}) {
        {
            FILE* raw_file{seq.Open({0, offset})};
            AutoFile file{raw_file};
            BOOST_REQUIRE(!file.IsNull());
            BOOST_CHECK_EQUAL(file.tell(), offset);
            BOOST_CHECK_EQUAL(FileTell64(raw_file), offset);
            file << uint8_t{99};
            file.seek(-1, SEEK_CUR);
            uint8_t value{0};
            file >> value;
            BOOST_CHECK_EQUAL(value, 99);
            file.seek(0, SEEK_END);
            BOOST_CHECK_EQUAL(file.tell(), offset + 1);
            BOOST_REQUIRE(file.Truncate(offset));
            BOOST_REQUIRE_EQUAL(file.fclose(), 0);
        }
        BOOST_CHECK_EQUAL(fs::file_size(seq.FileName({0, 0})), offset);
        BOOST_REQUIRE(seq.Flush({0, offset - 1}, /*finalize=*/true));
        BOOST_CHECK_EQUAL(fs::file_size(seq.FileName({0, 0})), offset - 1);
        // A high offset must never wrap and overwrite the start of the file.
        AutoFile file{seq.Open({0, 0}, /*read_only=*/true)};
        uint8_t value{0};
        file >> value;
        BOOST_CHECK_EQUAL(value, 42);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_filename)
{
    const auto data_dir = m_args.GetDataDirBase();

    FlatFilePos pos(456, 789);

    FlatFileSeq seq1(data_dir, "a", 16 * 1024);
    BOOST_CHECK_EQUAL(seq1.FileName(pos), data_dir / "a00456.dat");

    FlatFileSeq seq2(data_dir / "a", "b", 16 * 1024);
    BOOST_CHECK_EQUAL(seq2.FileName(pos), data_dir / "a" / "b00456.dat");

    // Check default constructor IsNull
    assert(FlatFilePos{}.IsNull());
}

BOOST_AUTO_TEST_CASE(flatfile_open)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 16 * 1024);

    std::string line1("A purely peer-to-peer version of electronic cash would allow online "
                      "payments to be sent directly from one party to another without going "
                      "through a financial institution.");
    std::string line2("Digital signatures provide part of the solution, but the main benefits are "
                      "lost if a trusted third party is still required to prevent double-spending.");

    size_t pos1 = 0;
    size_t pos2 = pos1 + GetSerializeSize(line1);

    // Write first line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos1))};
        file << LIMITED_STRING(line1, 256);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }

    // Attempt to append to file opened in read-only mode.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2), true)};
        BOOST_CHECK_THROW(file << LIMITED_STRING(line2, 256), std::ios_base::failure);
    }

    // Append second line to file.
    {
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};
        file << LIMITED_STRING(line2, 256);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }

    // Read text from file in read-only mode.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos1), true)};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line1);

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
    }

    // Read text from file with position offset.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(0, pos2))};

        file >> LIMITED_STRING(text, 256);
        BOOST_CHECK_EQUAL(text, line2);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }

    // Ensure another file in the sequence has no data.
    {
        std::string text;
        AutoFile file{seq.Open(FlatFilePos(1, pos2))};
        BOOST_CHECK_THROW(file >> LIMITED_STRING(text, 256), std::ios_base::failure);
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
}

BOOST_AUTO_TEST_CASE(flatfile_allocate)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 0), 1, out_of_space), 100U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 0))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 1, out_of_space), 0U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 100U);
    BOOST_CHECK(!out_of_space);

    BOOST_CHECK_EQUAL(seq.Allocate(FlatFilePos(0, 99), 2, out_of_space), 101U);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 99))), 200U);
    BOOST_CHECK(!out_of_space);
}

BOOST_AUTO_TEST_CASE(flatfile_flush)
{
    const auto data_dir = m_args.GetDataDirBase();
    FlatFileSeq seq(data_dir, "a", 100);

    bool out_of_space;
    seq.Allocate(FlatFilePos(0, 0), 1, out_of_space);

    // Flush without finalize should not truncate file.
    seq.Flush(FlatFilePos(0, 1));
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 100U);

    // Flush with finalize should truncate file.
    seq.Flush(FlatFilePos(0, 1), true);
    BOOST_CHECK_EQUAL(fs::file_size(seq.FileName(FlatFilePos(0, 1))), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
