#ifndef EDITIDENTITYDIALOG_H
#define EDITIDENTITYDIALOG_H

#include <QDialog>

namespace Ui {
    class EditIdentityDialog;
}
class IdentityTableModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

/** Dialog for editing an address and associated information.
 */
class EditIdentityDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewDataIdentity,
        NewIdentity,
        EditDataIdentity,
        EditIdentity,
		TransferIdentity
    };

    explicit EditIdentityDialog(Mode mode, QWidget *parent = 0);
    ~EditIdentityDialog();

    void setModel(WalletModel*,IdentityTableModel *model);
    void loadRow(int row);
	void loadIdentityDetails();

    QString getIdentity() const;
    void setIdentity(const QString &identity);

public Q_SLOTS:
    void accept();
	void on_okButton_clicked();
	void on_cancelButton_clicked();
	void on_addButton_clicked();
	void on_deleteButton_clicked();
	void reqSigsChanged();
	void expiryChanged(const QString& identity);
	void onCustomExpireCheckBoxChanged(bool toggled);
private:
    bool saveCurrentRow();

    Ui::EditIdentityDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    IdentityTableModel *model;
	WalletModel* walletModel;
    QString identity;
	QString expiredStr;
};

#endif // EDITIDENTITYDIALOG_H
