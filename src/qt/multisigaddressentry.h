// Copyright (c) 2016-2017 Duality Blockchain Solutions Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISIGADDRESSENTRY_H
#define MULTISIGADDRESSENTRY_H

#include <QFrame>

class PlatformStyle;
class WalletModel;

namespace Ui
{
    class MultisigAddressEntry;
}

class MultisigAddressEntry : public QFrame
{
    Q_OBJECT;

  public:
    explicit MultisigAddressEntry(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~MultisigAddressEntry();
    void setModel(WalletModel *model);
    bool validate();
    QString getWalletAddress();

  public Q_SLOTS:
    void setRemoveEnabled(bool enabled);
    void clear();

  Q_SIGNALS:
    void removeEntry(MultisigAddressEntry *entry);

  private:
    Ui::MultisigAddressEntry *ui;
    WalletModel *model;
    bool updateLabel(const QString &address);
    const PlatformStyle *platformStyle;

  private Q_SLOTS:
    void on_walletaddress_textChanged(const QString &address);
    void on_pasteButton_clicked();
    void on_deleteButton_clicked();
    void on_addressBookButton_clicked();
};

#endif // MULTISIGADDRESSENTRY_H 
