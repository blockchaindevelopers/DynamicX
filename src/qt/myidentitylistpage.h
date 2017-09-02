#ifndef MYIDENTITYLISTPAGE_H
#define MYIDENTITYLISTPAGE_H

#include <QDialog>
class PlatformStyle;
namespace Ui {
    class MyIdentityListPage;
}
class IdentityTableModel;
class OptionsModel;
class ClientModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of owned identities.
  */
class MyIdentityListPage : public QDialog
{
    Q_OBJECT

public:


    explicit MyIdentityListPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~MyIdentityListPage();

    void setModel(WalletModel*, IdentityTableModel *model);
    void setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	void showEvent ( QShowEvent * event );
public Q_SLOTS:
    void done(int retval);
	void on_signMultisigButton_clicked();
private:
	ClientModel* clientModel;
	WalletModel *walletModel;
    Ui::MyIdentityListPage *ui;
    IdentityTableModel *model;
    OptionsModel *optionsModel;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newIdentityToSelect;
	const PlatformStyle *platformStyle;
private Q_SLOTS:
    /** Create a new identity */
    void on_newIdentity_clicked();
    /** Copy identity of currently selected identity entry to clipboard */
    void on_copyIdentity_clicked();

    /** Edit currently selected identity entry (no button) */
    void on_editButton_clicked();
    /** Export button clicked */
    void on_exportButton_clicked();
    /** transfer the identity to a dynamic address  */
    void on_transferButton_clicked();
	void on_refreshButton_clicked();
	void on_newPubKey_clicked();
	void on_whitelistButton_clicked();
    /** Set button states based onf selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for identity book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to identity table */
    void selectNewIdentity(const QModelIndex &parent, int begin, int /*end*/);

Q_SIGNALS:
    void transferIdentity(QString addr);
};

#endif // MYIDENTITYLISTPAGE_H
