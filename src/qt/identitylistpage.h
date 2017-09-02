#ifndef IDENTITYLISTPAGE_H
#define IDENTITYLISTPAGE_H

#include <QDialog>
#include <map>
#include <utility>
class PlatformStyle;
namespace Ui {
    class IdentityListPage;
}
class IdentityTableModel;
class OptionsModel;
class WalletModel;
QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QMenu;
class QModelIndex;
class QKeyEvent;
QT_END_NAMESPACE

/** Widget that shows a list of owned identities.
  */
class IdentityListPage : public QDialog
{
    Q_OBJECT

public:
   

    explicit IdentityListPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~IdentityListPage();


    void setModel(WalletModel*, IdentityTableModel *model);
    void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }
	void keyPressEvent(QKeyEvent * event);
	void showEvent ( QShowEvent * event );
private:
    Ui::IdentityListPage *ui;
    IdentityTableModel *model;
    OptionsModel *optionsModel;
	WalletModel* walletModel;
    QString returnValue;
    QMenu *contextMenu;
    QAction *deleteAction; // to be able to explicitly disable it
    QString newIdentityToSelect;
	std::map<int, std::pair<std::string, std::string> > pageMap;
	int currentPage;
private Q_SLOTS:
	void on_signMultisigButton_clicked();
	void on_searchIdentity_clicked(std::string offer="");
	void on_prevButton_clicked();
	void on_nextButton_clicked();
    /** Create a new identity for receiving coins and / or add a new identity book entry */
    /** Copy identity of currently selected identity entry to clipboard */
    void on_copyIdentity_clicked();
	void on_messageButton_clicked();

    /** Set button states based on selected tab and selection */
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for identity book entry */
    void contextualMenu(const QPoint &point);
    /** New entry/entries were added to identity table */
    void selectNewIdentity(const QModelIndex &parent, int begin, int /*end*/);


};

#endif // IDENTITYLISTPAGE_H
