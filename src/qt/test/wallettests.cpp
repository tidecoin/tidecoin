// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/wallettests.h>
#include <qt/test/util.h>

#include <wallet/coincontrol.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pq/pq_scheme.h>
#include <qt/tidecoinamountfield.h>
#include <qt/tidecoinunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/walletmodeltransaction.h>
#include <limits>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/receivecoinsdialog.h>
#include <qt/receiverequestdialog.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendcoinsentry.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <chrono>
#include <memory>

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QObject>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QListView>
#include <QDialogButtonBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WalletContext;
using wallet::WalletDescriptor;
using wallet::WalletRescanReserver;

namespace
{
//! Press "Yes" or "Cancel" buttons in modal send confirmation dialog.
void ConfirmSend(QString* text = nullptr, QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QTimer::singleShot(0, [text, confirm_type]() {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("SendConfirmationDialog")) {
                SendConfirmationDialog* dialog = qobject_cast<SendConfirmationDialog*>(widget);
                if (text) *text = dialog->text();
                QAbstractButton* button = dialog->button(confirm_type);
                button->setEnabled(true);
                button->click();
            }
        }
    });
}

//! Send coins to address and return txid.
Txid SendCoins(CWallet& wallet, SendCoinsDialog& sendCoinsDialog, const CTxDestination& address, CAmount amount, bool rbf,
                  QMessageBox::StandardButton confirm_type = QMessageBox::Yes)
{
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    SendCoinsEntry* entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    entry->findChild<QValidatedLineEdit*>("payTo")->setText(QString::fromStdString(EncodeDestination(address)));
    entry->findChild<BitcoinAmountField*>("payAmount")->setValue(amount);
    sendCoinsDialog.findChild<QFrame*>("frameFee")
        ->findChild<QFrame*>("frameFeeSelection")
        ->findChild<QCheckBox*>("optInRBF")
        ->setCheckState(rbf ? Qt::Checked : Qt::Unchecked);
    Txid txid;
    boost::signals2::scoped_connection c(wallet.NotifyTransactionChanged.connect([&txid](const Txid& hash, ChangeType status) {
        if (status == CT_NEW) txid = hash;
    }));
    ConfirmSend(/*text=*/nullptr, confirm_type);
    bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
    assert(invoked);
    return txid;
}

//! Find index of txid in transaction list.
QModelIndex FindTx(const QAbstractItemModel& model, const Txid& txid)
{
    QString hash = QString::fromStdString(txid.ToString());
    int rows = model.rowCount({});
    for (int row = 0; row < rows; ++row) {
        QModelIndex index = model.index(row, 0, {});
        if (model.data(index, TransactionTableModel::TxHashRole) == hash) {
            return index;
        }
    }
    return {};
}

//! Invoke bumpfee on txid and check results.
void BumpFee(TransactionView& view, const Txid& txid, bool expectDisabled, std::string expectError, bool cancel)
{
    QTableView* table = view.findChild<QTableView*>("transactionView");
    QModelIndex index = FindTx(*table->selectionModel()->model(), txid);
    QVERIFY2(index.isValid(), "Could not find BumpFee txid");

    // Select row in table, invoke context menu, and make sure bumpfee action is
    // enabled or disabled as expected.
    QAction* action = view.findChild<QAction*>("bumpFeeAction");
    table->selectionModel()->select(index, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    action->setEnabled(expectDisabled);
    table->customContextMenuRequested({});
    QCOMPARE(action->isEnabled(), !expectDisabled);

    action->setEnabled(true);
    QString text;
    if (expectError.empty()) {
        ConfirmSend(&text, cancel ? QMessageBox::Cancel : QMessageBox::Yes);
    } else {
        ConfirmMessage(&text, 0ms);
    }
    action->trigger();
    QVERIFY(text.indexOf(QString::fromStdString(expectError)) != -1);
}

void CompareBalance(WalletModel& walletModel, CAmount expected_balance, QLabel* balance_label_to_check)
{
    BitcoinUnit unit = walletModel.getOptionsModel()->getDisplayUnit();
    QString balanceComparison = BitcoinUnits::formatWithUnit(unit, expected_balance, false, BitcoinUnits::SeparatorStyle::ALWAYS);
    QCOMPARE(balance_label_to_check->text().trimmed(), balanceComparison);
}

// Verify the 'useAvailableBalance' functionality. With and without manually selected coins.
// Case 1: No coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the total available balance
// Case 2: With coin control selected coins.
// 'useAvailableBalance' should fill the amount edit box with the sum of the selected coins values.
void VerifyUseAvailableBalance(SendCoinsDialog& sendCoinsDialog, const WalletModel& walletModel)
{
    // Verify first entry amount and "useAvailableBalance" button
    QVBoxLayout* entries = sendCoinsDialog.findChild<QVBoxLayout*>("entries");
    QVERIFY(entries->count() == 1); // only one entry
    SendCoinsEntry* send_entry = qobject_cast<SendCoinsEntry*>(entries->itemAt(0)->widget());
    QVERIFY(send_entry->getValue().amount == 0);
    // Now click "useAvailableBalance", check updated balance (the entire wallet balance should be set)
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == walletModel.getCachedBalance().balance);

    // Now manually select two coins and click on "useAvailableBalance". Then check updated balance
    // (only the sum of the selected coins should be set).
    int COINS_TO_SELECT = 2;
    auto coins = walletModel.wallet().listCoins();
    CAmount sum_selected_coins = 0;
    int selected = 0;
    QVERIFY(coins.size() == 1); // context check, coins received only on one destination
    for (const auto& [outpoint, tx_out] : coins.begin()->second) {
        sendCoinsDialog.getCoinControl()->Select(outpoint);
        sum_selected_coins += tx_out.txout.nValue;
        if (++selected == COINS_TO_SELECT) break;
    }
    QVERIFY(selected == COINS_TO_SELECT);

    // Now that we have 2 coins selected, "useAvailableBalance" should update the balance label only with
    // the sum of them.
    Q_EMIT send_entry->useAvailableBalance(send_entry);
    QVERIFY(send_entry->getValue().amount == sum_selected_coins);
}

void SyncUpWallet(const std::shared_ptr<CWallet>& wallet, interfaces::Node& node)
{
    WalletRescanReserver reserver(*wallet);
    reserver.reserve();
    CWallet::ScanResult result = wallet->ScanForWalletTransactions(Params().GetConsensus().hashGenesisBlock, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false);
    QCOMPARE(result.status, CWallet::ScanResult::SUCCESS);
    QCOMPARE(result.last_scanned_block, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    QVERIFY(result.last_failed_block.IsNull());
}

std::shared_ptr<CWallet> SetupDescriptorsWallet(interfaces::Node& node, TestChain100Setup& test, bool watch_only = false)
{
    std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    // GUI behavior does not depend on prefilling the default 1,000-entry pool.
    wallet->m_keypool_size = 4;
    wallet->LoadWallet();
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    if (watch_only) {
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    } else {
        wallet->SetupDescriptorScriptPubKeyMans();
    }

    // Add the coinbase key
    FlatSigningProvider provider;
    std::string error;
    std::string key_str;
    if (watch_only) {
        key_str = HexStr(test.coinbaseKey.GetPubKey());
    } else {
        key_str = EncodeSecret(test.coinbaseKey);
    }
    auto descs = Parse("combo(" + key_str + ")", provider, error, /* require_checksum=*/ false);
    assert(!descs.empty());
    assert(descs.size() == 1);
    auto& desc = descs.at(0);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    Assert(wallet->AddWalletDescriptor(w_desc, provider, "", false));
    const PKHash dest{test.coinbaseKey.GetPubKey()};
    wallet->SetAddressBook(dest, "", wallet::AddressPurpose::RECEIVE);
    wallet->SetLastBlockProcessed(105, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    SyncUpWallet(wallet, node);
    wallet->SetBroadcastTransactions(true);
    return wallet;
}

struct MiniGUI {
public:
    SendCoinsDialog sendCoinsDialog;
    TransactionView transactionView;
    OptionsModel optionsModel;
    std::unique_ptr<ClientModel> clientModel;
    std::unique_ptr<WalletModel> walletModel;

    MiniGUI(interfaces::Node& node, const PlatformStyle* platformStyle) : sendCoinsDialog(platformStyle), transactionView(platformStyle), optionsModel(node) {
        bilingual_str error;
        QVERIFY(optionsModel.Init(error));
        clientModel = std::make_unique<ClientModel>(node, &optionsModel);
    }

    void initModelForWallet(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet, const PlatformStyle* platformStyle)
    {
        WalletContext& context = *node.walletLoader().context();
        AddWallet(context, wallet);
        walletModel = std::make_unique<WalletModel>(interfaces::MakeWallet(context, wallet), *clientModel, platformStyle);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
        sendCoinsDialog.setModel(walletModel.get());
        transactionView.setModel(walletModel.get());
    }

};

void TestPSBTAmountRendering(WalletModel& walletModel, ClientModel* client_model)
{
    // Amount caps have a distinct result from nonpositive amounts.
    {
        SendCoinsRecipient recipient;
        recipient.address = QString::fromStdString(EncodeDestination(PKHash{}));
        recipient.amount = MAX_MONEY + 1;
        WalletModelTransaction excessive({recipient});
        QCOMPARE(walletModel.prepareTransaction(excessive, wallet::CCoinControl{}).status, WalletModel::AmountExceedsMaximum);
        recipient.amount = MAX_MONEY;
        auto second = recipient;
        second.address = QString::fromStdString(EncodeDestination(WitnessV0KeyHash{}));
        second.amount = 1;
        WalletModelTransaction excessive_sum({recipient, second});
        QCOMPARE(walletModel.prepareTransaction(excessive_sum, wallet::CCoinControl{}).status, WalletModel::AmountExceedsMaximum);
        recipient.amount = 0;
        WalletModelTransaction zero({recipient});
        QCOMPARE(walletModel.prepareTransaction(zero, wallet::CCoinControl{}).status, WalletModel::InvalidAmount);
    }
    // Exercise the actual dialog rendering with and without a loaded wallet.
    for (WalletModel* model : {&walletModel, static_cast<WalletModel*>(nullptr)}) {
        CMutableTransaction tx;
        tx.vin.emplace_back(Txid::FromUint256(uint256::ONE), 0);
        tx.vout.emplace_back(1000, CScript{} << OP_TRUE);
        PartiallySignedTransaction psbt(tx);
        PSBTOperationsDialog dialog(nullptr, model, client_model);
        dialog.openWithPSBT(psbt);
        auto* description = dialog.findChild<QTextEdit*>("transactionDescription");
        QVERIFY(description);
        QVERIFY(description->toPlainText().contains("Unable to calculate"));
        psbt.inputs[0].witness_utxo = CTxOut(1000, CScript{} << OP_TRUE);
        dialog.openWithPSBT(psbt);
        QVERIFY(description->toPlainText().contains("Pays transaction fee:"));
        QVERIFY(!description->toPlainText().contains("Unable to calculate"));
        for (CAmount value : {CAmount{-1}, std::numeric_limits<CAmount>::min(), std::numeric_limits<CAmount>::max()}) {
            auto invalid = psbt;
            invalid.tx->vout[0].nValue = value;
            dialog.openWithPSBT(invalid);
            QVERIFY(description->toPlainText().contains("Invalid transaction", Qt::CaseInsensitive));
            QVERIFY(!dialog.findChild<QPushButton*>("broadcastTransactionButton")->isEnabled());
            QVERIFY(!dialog.findChild<QPushButton*>("signTransactionButton")->isEnabled());
            dialog.signTransaction();
            QVERIFY(!dialog.findChild<QLabel*>("statusBar")->text().contains("ready", Qt::CaseInsensitive));
        }
        for (CAmount value : {std::numeric_limits<CAmount>::min(), std::numeric_limits<CAmount>::max()}) {
            auto invalid = psbt;
            invalid.inputs[0].witness_utxo.nValue = value;
            dialog.openWithPSBT(invalid);
            QVERIFY(description->toPlainText().contains("Invalid transaction", Qt::CaseInsensitive));
        }
        auto nondefault = psbt;
        CKey key;
        key.MakeNewKey(pq::SchemeId::FALCON_512);
        const auto pubkey = key.GetPubKey();
        const CScript witness_script = CScript{} << ToByteVector(pubkey) << OP_CHECKSIG;
        nondefault.inputs[0].witness_utxo.scriptPubKey = GetScriptForDestination(WitnessV1ScriptHash512{witness_script});
        nondefault.inputs[0].witness_script = witness_script;
        nondefault.inputs[0].sighash_type = SIGHASH_NONE;
        dialog.openWithPSBT(nondefault);
        QVERIFY(description->toPlainText().contains("Pays transaction fee:"));
        QVERIFY(!dialog.findChild<QPushButton*>("broadcastTransactionButton")->isEnabled());
        FlatSigningProvider provider;
        provider.keys.emplace(pubkey.GetID(), key);
        const auto txdata = PrecomputePSBTData(nondefault);
        constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
        QCOMPARE(SignPSBTInput(provider, nondefault, 0, &txdata, SIGHASH_NONE, nullptr, true, flags), common::PSBTError::OK);
        dialog.openWithPSBT(nondefault);
        QVERIFY(description->toPlainText().contains("Pays transaction fee:"));
        QVERIFY(dialog.findChild<QPushButton*>("broadcastTransactionButton")->isEnabled());
        auto invalid_sum = psbt;
        invalid_sum.tx->vout.assign(2, CTxOut(std::numeric_limits<CAmount>::max(), CScript{} << OP_TRUE));
        invalid_sum.outputs.resize(2);
        dialog.openWithPSBT(invalid_sum);
        QVERIFY(description->toPlainText().contains("Invalid transaction", Qt::CaseInsensitive));
    }

}

void TestPSBTSigningStatus(CWallet& wallet, WalletModel& model, ClientModel* client_model)
{
    FlatSigningProvider provider;
    std::vector<CKey> keys;
    std::vector<CScript> scripts;
    for (int i = 0; i < 2; ++i) {
        CKey key;
        key.MakeNewKey(pq::SchemeId::FALCON_512);
        keys.push_back(key);
        std::string error;
        auto descriptors = Parse("wpkh(" + EncodeSecret(key) + ")", provider, error, false);
        QVERIFY(!descriptors.empty());
        WalletDescriptor descriptor(std::move(descriptors[0]), 0, 0, 1, 1);
        QVERIFY(WITH_LOCK(wallet.cs_wallet, return bool(wallet.AddWalletDescriptor(descriptor, provider, "", false))));
        scripts.push_back(GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey())));
    }
    for (const auto& key : keys) {
        provider.keys.emplace(key.GetPubKey().GetID(), key);
        provider.pubkeys.emplace(key.GetPubKey().GetID(), key.GetPubKey());
    }
    CMutableTransaction previous;
    previous.vout = {CTxOut(1000, scripts[0]), CTxOut(1000, scripts[0]), CTxOut(1000, scripts[1])};
    CMutableTransaction tx;
    for (int i = 0; i < 3; ++i) tx.vin.emplace_back(previous.GetHash(), i);
    tx.vout.emplace_back(2000, CScript{} << OP_TRUE);
    PartiallySignedTransaction original(tx);
    for (auto& input : original.inputs) input.non_witness_utxo = MakeTransactionRef(previous);
    PSBTOperationsDialog dialog(nullptr, &model, client_model);
    auto* sign = dialog.findChild<QPushButton*>("signTransactionButton");
    auto* broadcast = dialog.findChild<QPushButton*>("broadcastTransactionButton");
    auto* status = dialog.findChild<QLabel*>("statusBar");
    auto request = original;
    for (auto& input : request.inputs) input.sighash_type = SIGHASH_NONE;
    dialog.openWithPSBT(request);
    QVERIFY(sign->isEnabled());
    dialog.copyToClipboard();
    const auto before = QApplication::clipboard()->text();
    sign->click();
    for (int i = 0; i < 3; ++i) QVERIFY(status->text().contains(QString("Input %1: requested mode 1, declared mode 2").arg(i)));
    QVERIFY(status->text().contains("explicitly"));
    QVERIFY(!broadcast->isEnabled());
    dialog.copyToClipboard();
    QCOMPARE(QApplication::clipboard()->text(), before);

    // A global request cannot silently adopt two owned inputs' different modes.
    request.inputs[0].sighash_type = SIGHASH_ALL;
    dialog.openWithPSBT(request);
    dialog.copyToClipboard();
    const auto mixed_before = QApplication::clipboard()->text();
    sign->click();
    QVERIFY(!status->text().contains("Input 0:"));
    QVERIFY(status->text().contains("Input 1:"));
    QVERIFY(status->text().contains("Input 2:"));
    QVERIFY(!broadcast->isEnabled());
    dialog.copyToClipboard();
    QCOMPARE(QApplication::clipboard()->text(), mixed_before);

    // This transaction could be fully signed; invalid amounts must prevent it.
    request = original;
    request.tx->vout[0].nValue = MAX_MONEY + 1;
    dialog.openWithPSBT(request);
    QVERIFY(!sign->isEnabled());
    dialog.signTransaction();
    QVERIFY(!broadcast->isEnabled());
    QVERIFY(!status->text().contains("ready", Qt::CaseInsensitive));

    for (int mode : {0, -1, 0x101, 4, 0x22, 0x41, 0x43}) {
        request = original;
        request.inputs[0].sighash_type = mode;
        dialog.openWithPSBT(request);
        QVERIFY(status->text().contains("Input 0:"));
        QVERIFY(status->text().contains("missing some information"));
        QVERIFY(!broadcast->isEnabled());
        dialog.copyToClipboard();
        const auto before_sign = QApplication::clipboard()->text();
        dialog.signTransaction();
        QVERIFY(status->text().contains("Failed to sign transaction"));
        QVERIFY(!broadcast->isEnabled());
        dialog.copyToClipboard();
        QCOMPARE(QApplication::clipboard()->text(), before_sign);
    }

    // An already final constant-one signature remains valid and its warning
    // must appear beside, rather than replace, the ready status.
    const CScript legacy = CScript{} << ToByteVector(keys[1].GetPubKey()) << OP_CHECKSIG;
    previous.vout[1].scriptPubKey = legacy;
    tx.vin.resize(2);
    for (auto& input : tx.vin) input.prevout.hash = previous.GetHash();
    request = PartiallySignedTransaction(tx);
    for (auto& input : request.inputs) input.non_witness_utxo = MakeTransactionRef(previous);
    const auto data = PrecomputePSBTData(request);
    constexpr unsigned flags{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_PQ_STRICT | SCRIPT_VERIFY_WITNESS_V1_512};
    QCOMPARE(SignPSBTInput(provider, request, 0, &data, SIGHASH_ALL, nullptr, true, flags), common::PSBTError::OK);
    std::vector<unsigned char> signature;
    QVERIFY(keys[1].Sign(uint256::ONE, signature, false, 0, false));
    signature.push_back(SIGHASH_SINGLE);
    request.inputs[1].final_script_sig = CScript{} << signature;
    dialog.openWithPSBT(request);
    QVERIFY(broadcast->isEnabled());
    QVERIFY(status->text().contains("ready for broadcast"));
    QVERIFY(status->text().contains("Input 1:"));
}

//! Simple qt wallet tests.
//
// Test widgets can be debugged interactively calling show() on them and
// manually running the event loop, e.g.:
//
//     sendCoinsDialog.show();
//     QEventLoop().exec();
//
// This also requires overriding the default minimal Qt platform:
//
//     QT_QPA_PLATFORM=xcb     build/bin/test_tidecoin-qt  # Linux
//     QT_QPA_PLATFORM=windows build/bin/test_tidecoin-qt  # Windows
//     QT_QPA_PLATFORM=cocoa   build/bin/test_tidecoin-qt  # macOS
void TestGUI(interfaces::Node& node, const std::shared_ptr<CWallet>& wallet)
{
    // Create widgets for sending coins and listing transactions.
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;
    TransactionView& transactionView = mini_gui.transactionView;

    TestPSBTAmountRendering(walletModel, mini_gui.clientModel.get());
    if (!walletModel.wallet().privateKeysDisabled()) TestPSBTSigningStatus(*wallet, walletModel, mini_gui.clientModel.get());

    // Exercise the send dialog's actual message for an excessive aggregate.
    {
        SendCoinsRecipient first, second;
        first.address = QString::fromStdString(EncodeDestination(PKHash{}));
        second.address = QString::fromStdString(EncodeDestination(WitnessV0KeyHash{}));
        first.amount = MAX_MONEY;
        second.amount = COIN;
        sendCoinsDialog.pasteEntry(first);
        sendCoinsDialog.pasteEntry(second);
        QString message;
        const auto connection = QObject::connect(&sendCoinsDialog, &SendCoinsDialog::message, [&](const QString&, const QString& text, unsigned int) { message = text; });
        const bool invoked = QMetaObject::invokeMethod(&sendCoinsDialog, "sendButtonClicked", Q_ARG(bool, false));
        QObject::disconnect(connection);
        QVERIFY(invoked);
        QVERIFY(message.contains("total amount exceeds the maximum permitted amount"));
        QVERIFY(!message.contains("larger than 0"));
        sendCoinsDialog.clear();
    }

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalance(), sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Check 'UseAvailableBalance' functionality
    VerifyUseAvailableBalance(sendCoinsDialog, walletModel);

    // Send two transactions, and verify they are added to transaction list.
    TransactionTableModel* transactionTableModel = walletModel.getTransactionTableModel();
    QCOMPARE(transactionTableModel->rowCount({}), 105);
    Txid txid1 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false);
    Txid txid2 = SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 10 * COIN, /*rbf=*/true);
    // Transaction table model updates on a QueuedConnection, so process events to ensure it's updated.
    qApp->processEvents();
    QCOMPARE(transactionTableModel->rowCount({}), 107);
    QVERIFY(FindTx(*transactionTableModel, txid1).isValid());
    QVERIFY(FindTx(*transactionTableModel, txid2).isValid());

    // Call bumpfee. Test canceled fullrbf bump, canceled bip-125-rbf bump, passing bump, and then failing bump.
    BumpFee(transactionView, txid1, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/true);
    BumpFee(transactionView, txid2, /*expectDisabled=*/false, /*expectError=*/{}, /*cancel=*/false);
    BumpFee(transactionView, txid2, /*expectDisabled=*/true, /*expectError=*/"already bumped", /*cancel=*/false);

    // Check current balance on OverviewPage
    OverviewPage overviewPage(platformStyle.get());
    overviewPage.setWalletModel(&walletModel);
    walletModel.pollBalanceChanged(); // Manual balance polling update
    CompareBalance(walletModel, walletModel.wallet().getBalance(), overviewPage.findChild<QLabel*>("labelBalance"));

    // Check Request Payment button
    ReceiveCoinsDialog receiveCoinsDialog(platformStyle.get());
    receiveCoinsDialog.setModel(&walletModel);
    RecentRequestsTableModel* requestTableModel = walletModel.getRecentRequestsTableModel();

    // Label input
    QLineEdit* labelInput = receiveCoinsDialog.findChild<QLineEdit*>("reqLabel");
    labelInput->setText("TEST_LABEL_1");

    // Amount input
    BitcoinAmountField* amountInput = receiveCoinsDialog.findChild<BitcoinAmountField*>("reqAmount");
    amountInput->setValue(1);

    // Message input
    QLineEdit* messageInput = receiveCoinsDialog.findChild<QLineEdit*>("reqMessage");
    messageInput->setText("TEST_MESSAGE_1");
    int initialRowCount = requestTableModel->rowCount({});
    QPushButton* requestPaymentButton = receiveCoinsDialog.findChild<QPushButton*>("receiveButton");
    requestPaymentButton->click();
    QString address;
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (widget->inherits("ReceiveRequestDialog")) {
            ReceiveRequestDialog* receiveRequestDialog = qobject_cast<ReceiveRequestDialog*>(widget);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("payment_header")->text(), QString("Payment information"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("uri_tag")->text(), QString("URI:"));
            QString uri = receiveRequestDialog->QObject::findChild<QLabel*>("uri_content")->text();
            QCOMPARE(uri.count("tidecoin:"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("address_tag")->text(), QString("Address:"));
            QVERIFY(address.isEmpty());
            address = receiveRequestDialog->QObject::findChild<QLabel*>("address_content")->text();
            QVERIFY(!address.isEmpty());

            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("scheme_tag")->text(), QString("Scheme:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("scheme_content")->text(), QString("Falcon-512"));

            QCOMPARE(uri.count("amount=0.00000001"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_tag")->text(), QString("Amount:"));
            const BitcoinUnit display_unit = walletModel.getOptionsModel()->getDisplayUnit();
            const QString expected_amount = BitcoinUnits::formatWithUnit(display_unit, CAmount{1});
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("amount_content")->text(), expected_amount);

            QCOMPARE(uri.count("label=TEST_LABEL_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_tag")->text(), QString("Label:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("label_content")->text(), QString("TEST_LABEL_1"));

            QCOMPARE(uri.count("message=TEST_MESSAGE_1"), 2);
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_tag")->text(), QString("Message:"));
            QCOMPARE(receiveRequestDialog->QObject::findChild<QLabel*>("message_content")->text(), QString("TEST_MESSAGE_1"));
        }
    }

    // Clear button
    QPushButton* clearButton = receiveCoinsDialog.findChild<QPushButton*>("clearButton");
    clearButton->click();
    QCOMPARE(labelInput->text(), QString(""));
    QCOMPARE(amountInput->value(), CAmount(0));
    QCOMPARE(messageInput->text(), QString(""));

    // Check addition to history
    int currentRowCount = requestTableModel->rowCount({});
    QCOMPARE(currentRowCount, initialRowCount+1);

    // Check addition to wallet
    std::vector<std::string> requests = walletModel.wallet().getAddressReceiveRequests();
    QCOMPARE(requests.size(), size_t{1});
    RecentRequestEntry entry;
    DataStream{MakeUCharSpan(requests[0])} >> entry;
    QCOMPARE(entry.nVersion, int{1});
    QCOMPARE(entry.id, int64_t{1});
    QVERIFY(entry.date.isValid());
    QCOMPARE(entry.recipient.address, address);
    QCOMPARE(entry.recipient.label, QString{"TEST_LABEL_1"});
    QCOMPARE(entry.recipient.amount, CAmount{1});
    QCOMPARE(entry.recipient.message, QString{"TEST_MESSAGE_1"});
    QCOMPARE(entry.recipient.sPaymentRequest, std::string{});
    QCOMPARE(entry.recipient.authenticatedMerchant, QString{});

    // Check Remove button
    QTableView* table = receiveCoinsDialog.findChild<QTableView*>("recentRequestsView");
    table->selectRow(currentRowCount-1);
    QPushButton* removeRequestButton = receiveCoinsDialog.findChild<QPushButton*>("removeRequestButton");
    removeRequestButton->click();
    QCOMPARE(requestTableModel->rowCount({}), currentRowCount-1);

    // Check removal from wallet
    QCOMPARE(walletModel.wallet().getAddressReceiveRequests().size(), size_t{0});
}

void TestGUIWatchOnly(interfaces::Node& node, TestChain100Setup& test)
{
    const std::shared_ptr<CWallet>& wallet = SetupDescriptorsWallet(node, test, /*watch_only=*/true);

    // Create widgets and init models
    std::unique_ptr<const PlatformStyle> platformStyle(PlatformStyle::instantiate("other"));
    MiniGUI mini_gui(node, platformStyle.get());
    mini_gui.initModelForWallet(node, wallet, platformStyle.get());
    WalletModel& walletModel = *mini_gui.walletModel;
    SendCoinsDialog& sendCoinsDialog = mini_gui.sendCoinsDialog;

    TestPSBTAmountRendering(walletModel, mini_gui.clientModel.get());
    if (!walletModel.wallet().privateKeysDisabled()) TestPSBTSigningStatus(*wallet, walletModel, mini_gui.clientModel.get());

    // Update walletModel cached balance which will trigger an update for the 'labelBalance' QLabel.
    walletModel.pollBalanceChanged();
    // Check balance in send dialog
    CompareBalance(walletModel, walletModel.wallet().getBalances().balance,
                   sendCoinsDialog.findChild<QLabel*>("labelBalance"));

    // Set change address
    sendCoinsDialog.getCoinControl()->destChange = PKHash{test.coinbaseKey.GetPubKey()};

    // Time to reject "save" PSBT dialog ('SendCoins' locks the main thread until the dialog receives the event).
    QTimer timer;
    timer.setInterval(500);
    QObject::connect(&timer, &QTimer::timeout, [&](){
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (widget->inherits("QMessageBox") && widget->objectName().compare("psbt_copied_message") == 0) {
                QMessageBox* dialog = qobject_cast<QMessageBox*>(widget);
                QAbstractButton* button = dialog->button(QMessageBox::Discard);
                button->setEnabled(true);
                button->click();
                timer.stop();
                break;
            }
        }
    });
    timer.start(500);

    // Send tx and verify PSBT copied to the clipboard.
    SendCoins(*wallet.get(), sendCoinsDialog, PKHash(), 5 * COIN, /*rbf=*/false, QMessageBox::Save);
    const std::string& psbt_string = QApplication::clipboard()->text().toStdString();
    QVERIFY(!psbt_string.empty());

    // Decode psbt
    std::optional<std::vector<unsigned char>> decoded_psbt = DecodeBase64(psbt_string);
    QVERIFY(decoded_psbt);
    PartiallySignedTransaction psbt;
    std::string err;
    QVERIFY(DecodeRawPSBT(psbt, MakeByteSpan(*decoded_psbt), err));
}

void TestGUI(interfaces::Node& node)
{
    // Set up wallet and chain with 105 blocks (5 mature blocks for spending).
    TestChain100Setup test;
    for (int i = 0; i < 5; ++i) {
        test.CreateAndProcessBlock({}, GetScriptForRawPubKey(test.coinbaseKey.GetPubKey()));
    }
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    // "Full" GUI tests, use descriptor wallet
    const std::shared_ptr<CWallet>& desc_wallet = SetupDescriptorsWallet(node, test);
    TestGUI(node, desc_wallet);

    // Legacy watch-only wallet test
    // Verify PSBT creation.
    TestGUIWatchOnly(node, test);
}

} // namespace

void WalletTests::walletTests()
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping WalletTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
                      "with 'QT_QPA_PLATFORM=cocoa test_tidecoin-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif
    TestGUI(m_node);
}
