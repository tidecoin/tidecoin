// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/addressbooktests.h>
#include <qt/test/util.h>
#include <test/util/setup_common.h>

#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <qt/addressbookpage.h>
#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/editaddressdialog.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/walletmodel.h>

#include <key.h>
#include <key_io.h>
#include <wallet/wallet.h>
#include <wallet/test/util.h>
#include <walletinitinterface.h>

#include <chrono>

#include <QApplication>
#include <QLineEdit>
#include <QMessageBox>
#include <QTableView>
#include <QTimer>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WalletContext;

namespace
{

class AddressBookFailDatabase : public wallet::MockableDatabase
{
    class Batch : public wallet::MockableBatch {
        const bool& m_fail_commit;
    public:
        Batch(wallet::MockableData& records, bool pass, const bool& fail_commit)
            : MockableBatch(records, pass), m_fail_commit(fail_commit) {}
        bool TxnCommit() override { return !m_fail_commit && MockableBatch::TxnCommit(); }
    };
public:
    bool fail_commit{false};
    std::unique_ptr<wallet::DatabaseBatch> MakeBatch() override { return std::make_unique<Batch>(m_records, m_pass, fail_commit); }
};

/**
 * Fill the edit address dialog box with data, submit it, and ensure that
 * the resulting message meets expectations.
 */
void EditAddressAndSubmit(
        EditAddressDialog* dialog,
        const QString& label, const QString& address, QString expected_msg)
{
    QString warning_text;

    dialog->findChild<QLineEdit*>("labelEdit")->setText(label);
    dialog->findChild<QValidatedLineEdit*>("addressEdit")->setText(address);

    ConfirmMessage(&warning_text, 5ms);
    dialog->accept();
    QCOMPARE(warning_text, expected_msg);
}

/**
 * Test adding various send addresses to the address book.
 *
 * There are three cases tested:
 *
 *   - new_address: a new address which should add as a send address successfully.
 *   - existing_s_address: an existing sending address which won't add successfully.
 *   - existing_r_address: an existing receiving address which won't add successfully.
 *
 * In each case, verify the resulting state of the address book and optionally
 * the warning message presented to the user.
 */
void TestAddAddressesToSendBook(interfaces::Node& node)
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);
    auto database = std::make_unique<AddressBookFailDatabase>();
    auto& db = *database;
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", std::move(database));
    // Address-book behavior does not depend on the default keypool size.
    wallet->m_keypool_size = 4;
    wallet->LoadWallet();
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(wallet->cs_wallet);
        wallet->SetupDescriptorScriptPubKeyMans();
    }

    auto build_address{[]() {
        const WitnessV0KeyHash dest{GenerateRandomKey(pq::SchemeId::FALCON_512).GetPubKey()};
        return std::make_pair(dest, QString::fromStdString(EncodeDestination(dest)));
    }};

    CTxDestination r_key_dest, s_key_dest;

    // Add a preexisting "receive" entry in the address book.
    QString preexisting_r_address;
    QString r_label("already here (r)");

    // Add a preexisting "send" entry in the address book.
    QString preexisting_s_address;
    QString s_label("already here (s)");

    // Define a new address (which should add to the address book successfully).
    QString new_address_a;
    QString new_address_b;

    std::tie(r_key_dest, preexisting_r_address) = build_address();
    std::tie(s_key_dest, preexisting_s_address) = build_address();
    std::tie(std::ignore, new_address_a) = build_address();
    std::tie(std::ignore, new_address_b) = build_address();

    {
        LOCK(wallet->cs_wallet);
        wallet->SetAddressBook(r_key_dest, r_label.toStdString(), wallet::AddressPurpose::RECEIVE);
        wallet->SetAddressBook(s_key_dest, s_label.toStdString(), wallet::AddressPurpose::SEND);
    }

    auto check_addbook_size = [&wallet](int expected_size) {
        LOCK(wallet->cs_wallet);
        QCOMPARE(static_cast<int>(wallet->m_address_book.size()), expected_size);
    };

    // We should start with the two addresses we added earlier and nothing else.
    check_addbook_size(2);

    // Initialize relevant QT models.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    OptionsModel optionsModel(node);
    bilingual_str error;
    QVERIFY(optionsModel.Init(error));
    ClientModel clientModel(node, &optionsModel);
    WalletContext& context = *node.walletLoader().context();
    AddWallet(context, wallet);
    WalletModel walletModel(interfaces::MakeWallet(context, wallet), clientModel, platformStyle.get());
    RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    EditAddressDialog editAddressDialog(EditAddressDialog::NewSendingAddress);
    editAddressDialog.setModel(walletModel.getAddressTableModel());

    AddressBookPage address_book{platformStyle.get(), AddressBookPage::ForEditing, AddressBookPage::SendingTab};
    address_book.setModel(walletModel.getAddressTableModel());
    auto table_view = address_book.findChild<QTableView*>("tableView");
    QCOMPARE(table_view->model()->rowCount(), 1);

    EditAddressAndSubmit(
        &editAddressDialog, QString("uhoh"), preexisting_r_address,
        QString(
            "Address \"%1\" already exists as a receiving address with label "
            "\"%2\" and so cannot be added as a sending address."
            ).arg(preexisting_r_address).arg(r_label));
    check_addbook_size(2);
    QCOMPARE(table_view->model()->rowCount(), 1);

    EditAddressAndSubmit(
        &editAddressDialog, QString("uhoh, different"), preexisting_s_address,
        QString(
            "The entered address \"%1\" is already in the address book with "
            "label \"%2\"."
            ).arg(preexisting_s_address).arg(s_label));
    check_addbook_size(2);
    QCOMPARE(table_view->model()->rowCount(), 1);

    // Submit a new address which should add successfully - we expect the
    // warning message to be blank.
    EditAddressAndSubmit(
        &editAddressDialog, QString("io - new A"), new_address_a, QString(""));
    check_addbook_size(3);
    QCOMPARE(table_view->model()->rowCount(), 2);

    EditAddressAndSubmit(
        &editAddressDialog, QString("io - new B"), new_address_b, QString(""));
    check_addbook_size(4);
    QCOMPARE(table_view->model()->rowCount(), 3);

    auto search_line = address_book.findChild<QLineEdit*>("searchLineEdit");

    search_line->setText(r_label);
    QCOMPARE(table_view->model()->rowCount(), 0);

    search_line->setText(s_label);
    QCOMPARE(table_view->model()->rowCount(), 1);

    search_line->setText("io");
    QCOMPARE(table_view->model()->rowCount(), 2);

    // Check wildcard "?".
    search_line->setText("io?new");
    QCOMPARE(table_view->model()->rowCount(), 0);
    search_line->setText("io???new");
    QCOMPARE(table_view->model()->rowCount(), 2);

    // Check wildcard "*".
    search_line->setText("io*new");
    QCOMPARE(table_view->model()->rowCount(), 2);
    search_line->setText("*");
    QCOMPARE(table_view->model()->rowCount(), 3);

    search_line->setText(preexisting_r_address);
    QCOMPARE(table_view->model()->rowCount(), 0);

    search_line->setText(preexisting_s_address);
    QCOMPARE(table_view->model()->rowCount(), 1);

    search_line->setText(new_address_a);
    QCOMPARE(table_view->model()->rowCount(), 1);

    search_line->setText(new_address_b);
    QCOMPARE(table_view->model()->rowCount(), 1);

    search_line->setText("");
    QCOMPARE(table_view->model()->rowCount(), 3);

    // A failed delete must leave disk, wallet and model unchanged, and editing
    // must not add a replacement after failing to remove the original address.
    auto* model = walletModel.getAddressTableModel();
    const auto [replacement_dest, replacement_address] = build_address();
    const auto records = db.m_records;
    for (bool fail_commit : {false, true}) {
        db.m_pass = fail_commit; // Otherwise fail at begin.
        db.fail_commit = fail_commit;
        const int row = model->lookupAddress(preexisting_s_address);
        QVERIFY(row >= 0);
        QVERIFY(!model->removeRows(row, 1));
        QCOMPARE(model->getEditStatus(), AddressTableModel::ADDRESS_BOOK_FAILURE);
        QVERIFY(!model->setData(model->index(row, AddressTableModel::Address, {}), replacement_address, Qt::EditRole));
        QCOMPARE(model->getEditStatus(), AddressTableModel::ADDRESS_BOOK_FAILURE);
        QVERIFY(db.m_records == records);
        {
            LOCK(wallet->cs_wallet);
            QVERIFY(wallet->m_address_book.contains(s_key_dest));
            QVERIFY(!wallet->m_address_book.contains(replacement_dest));
        }
        QApplication::processEvents();
        QCOMPARE(table_view->model()->rowCount(), 3);
        QCOMPARE(model->labelForAddress(preexisting_s_address), s_label);

        EditAddressDialog edit(EditAddressDialog::EditSendingAddress);
        edit.setModel(model);
        edit.loadRow(row);
        EditAddressAndSubmit(&edit, s_label, replacement_address,
            QString("Could not save the address book change. Please check the wallet's debug log."));
        QCOMPARE(edit.result(), int(QDialog::Rejected));

        search_line->setText(preexisting_s_address);
        table_view->selectRow(0);
        QString warning;
        ConfirmMessage(&warning, 0ms);
        QVERIFY(QMetaObject::invokeMethod(&address_book, "on_deleteAddress_clicked"));
        QCOMPARE(warning, QString("Could not delete the address book entry. Please check the wallet's debug log."));
        QVERIFY(db.m_records == records);
        QCOMPARE(table_view->model()->rowCount(), 1);
        search_line->setText("");
    }
    db.m_pass = true;
    db.fail_commit = false;
    QVERIFY(model->removeRows(model->lookupAddress(preexisting_s_address), 1));
    QCOMPARE(model->getEditStatus(), AddressTableModel::OK);
    QApplication::processEvents();
    QCOMPARE(table_view->model()->rowCount(), 2);
    QCOMPARE(model->lookupAddress(preexisting_s_address), -1);
    check_addbook_size(3);
    QVERIFY(!walletModel.wallet().getAddress(s_key_dest, nullptr, nullptr));
}

} // namespace

void AddressBookTests::addressBookTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping AddressBookTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                      "with 'QT_QPA_PLATFORM=cocoa test_tidecoin-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif
    TestAddAddressesToSendBook(m_node);
}
