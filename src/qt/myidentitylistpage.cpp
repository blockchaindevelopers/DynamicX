/*
 * Dynamic Developers 2014
 */
#include "myidentitylistpage.h"
#include "ui_myidentitylistpage.h"
#include "identitytablemodel.h"
#include "clientmodel.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"
#include "dynamicgui.h"
#include "editidentitydialog.h"
#include "signrawtxdialog.h"
#include "mywhitelistofferdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include "rpcserver.h"

using namespace std;
extern const CRPCTable tableRPC;
MyIdentityListPage::MyIdentityListPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MyIdentityListPage),
    model(0),
    optionsModel(0),
	platformStyle(platformStyle)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->exportButton->setIcon(QIcon());
		ui->newIdentity->setIcon(QIcon());
		ui->transferButton->setIcon(QIcon());
		ui->editButton->setIcon(QIcon());
		ui->copyIdentity->setIcon(QIcon());
		ui->refreshButton->setIcon(QIcon());
		ui->newPubKey->setIcon(QIcon());
		ui->whitelistButton->setIcon(QIcon());
		ui->signMultisigButton->setIcon(QIcon());
	}
	else
	{
		ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/export"));
		ui->newIdentity->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/add"));
		ui->transferButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/identity"));
		ui->editButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/editsys"));
		ui->copyIdentity->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/editcopy"));
		ui->refreshButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/refresh"));
		ui->newPubKey->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/add"));
		ui->whitelistButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/address-book"));
		ui->signMultisigButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/key"));
		
	}

    ui->labelExplanation->setText(tr("These are your registered Dynamic Identities. Identity operations (create, update, transfer) take 2-5 minutes to become active."));
	
	
    // Context menu actions
    QAction *copyIdentityAction = new QAction(ui->copyIdentity->text(), this);
    QAction *editAction = new QAction(tr("Edit"), this);
    QAction *transferIdentityAction = new QAction(tr("Transfer"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyIdentityAction);
    contextMenu->addAction(editAction);
    contextMenu->addSeparator();
    contextMenu->addAction(transferIdentityAction);

    // Connect signals for context menu actions
    connect(copyIdentityAction, SIGNAL(triggered()), this, SLOT(on_copyIdentity_clicked()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(on_editButton_clicked()));
    connect(transferIdentityAction, SIGNAL(triggered()), this, SLOT(on_transferButton_clicked()));

	connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(on_editButton_clicked()));
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

}

MyIdentityListPage::~MyIdentityListPage()
{
    delete ui;
}
void MyIdentityListPage::on_signMultisigButton_clicked()
{
	SignRawTxDialog dlg;   
	dlg.exec();
}
void MyIdentityListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;
    /*if(walletModel->getEncryptionStatus() == WalletModel::Locked)
	{
        ui->labelExplanation->setText(tr("<font color='blue'>WARNING: Your wallet is currently locked. For security purposes you'll need to enter your passphrase in order to interact with Dynamic Identities. Because your wallet is locked you must manually refresh this table after creating or updating an Identity. </font> <a href=\"http://lockedwallet.dynamic.org\">more info</a><br><br>These are your registered Dynamic Identities. Identity updates take 1 confirmation to appear in this table."));
		ui->labelExplanation->setTextFormat(Qt::RichText);
		ui->labelExplanation->setTextInteractionFlags(Qt::TextBrowserInteraction);
		ui->labelExplanation->setOpenExternalLinks(true);
    }*/
}
void MyIdentityListPage::setModel(WalletModel *walletModel, IdentityTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

  
    // Receive filter
    proxyModel->setFilterRole(IdentityTableModel::TypeRole);
    proxyModel->setFilterFixedString(IdentityTableModel::Identity);

    ui->tableView->setModel(proxyModel);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);

    // Set column widths
    ui->tableView->setColumnWidth(0, 500); //identity name
	ui->tableView->setColumnWidth(1, 100); //multisig
    ui->tableView->setColumnWidth(2, 150); //expires on
    ui->tableView->setColumnWidth(3, 75); //expired status
	ui->tableView->setColumnWidth(4, 150); //buyerrating
	ui->tableView->setColumnWidth(5, 150); //sellerrrating
	ui->tableView->setColumnWidth(6, 0); //arbiterrating
	

    ui->tableView->horizontalHeader()->setStretchLastSection(true);

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created identity
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewIdentity(QModelIndex,int,int)));

    selectionChanged();
}

void MyIdentityListPage::setOptionsModel(ClientModel* clientmodel, OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
	this->clientModel = clientmodel;
}

void MyIdentityListPage::on_copyIdentity_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, IdentityTableModel::Name);
}

void MyIdentityListPage::on_editButton_clicked()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;
	QString status = indexes.at(0).data(IdentityTableModel::ExpiredRole).toString();
	if(status == QString("expired"))
	{
           QMessageBox::information(this, windowTitle(),
           tr("You cannot edit this identity because it has expired"),
               QMessageBox::Ok, QMessageBox::Ok);
		   return;
	}

    EditIdentityDialog dlg(EditIdentityDialog::EditIdentity);
    dlg.setModel(walletModel, model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void MyIdentityListPage::on_transferButton_clicked()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;
	QString status = indexes.at(0).data(IdentityTableModel::ExpiredRole).toString();
	if(status == QString("pending"))
	{
           QMessageBox::information(this, windowTitle(),
           tr("This identity is still pending, click the refresh button once the identity confirms and try again"),
               QMessageBox::Ok, QMessageBox::Ok);
		   return;
	}
	if(status == QString("expired"))
	{
           QMessageBox::information(this, windowTitle(),
           tr("You cannot transfer this identity because it has expired"),
               QMessageBox::Ok, QMessageBox::Ok);
		   return;
	}
    EditIdentityDialog dlg(EditIdentityDialog::TransferIdentity);
    dlg.setModel(walletModel, model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}
void MyIdentityListPage::on_refreshButton_clicked()
{
    if(!model)
        return;
    model->refreshIdentityTable();
}
void MyIdentityListPage::on_whitelistButton_clicked()
{
    MyWhitelistOfferDialog dlg(platformStyle);
	dlg.setModel(walletModel);
    dlg.exec();    
}
void MyIdentityListPage::on_newIdentity_clicked()
{
    if(!model)
        return;

    EditIdentityDialog dlg(EditIdentityDialog::NewIdentity);
    dlg.setModel(walletModel,model);
    if(dlg.exec())
    {
        newIdentityToSelect = dlg.getIdentity();
    }
}
void MyIdentityListPage::on_newPubKey_clicked()
{
	UniValue params;
	UniValue result = tableRPC.execute("generatepublickey", params);
	if (result.type() == UniValue::VARR)
	{
		const UniValue &resultArray = result.get_array();
		const QString  &resQStr = QString::fromStdString(resultArray[0].get_str());
		QApplication::clipboard()->setText(resQStr, QClipboard::Clipboard);
		QApplication::clipboard()->setText(resQStr, QClipboard::Selection);
		QMessageBox::information(this, tr("New Public Key For Identity Transfer"),
			resQStr + tr(" has been copied to your clipboard! IMPORTANT: This key is for one-time use only! Do not re-use public keys for multiple identities or transfers."),
			QMessageBox::Ok, QMessageBox::Ok);
		
	}
	else
	 	QMessageBox::critical(this, tr("New Public Key For Identity Transfer"),
			tr("Could not generate a new public key!"),
			QMessageBox::Ok, QMessageBox::Ok);
				
}
void MyIdentityListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyIdentity->setEnabled(true);
		ui->transferButton->setEnabled(true);
		ui->editButton->setEnabled(true);
    }
    else
    {
        ui->copyIdentity->setEnabled(false);
		ui->transferButton->setEnabled(false);
		ui->editButton->setEnabled(false);
    }
}

void MyIdentityListPage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;

    // Figure out which identity was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(IdentityTableModel::Name);
    Q_FOREACH (const QModelIndex& index, indexes)
    {
        QVariant identity = table->model()->data(index);
        returnValue = identity.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no identity entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void MyIdentityListPage::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Identity Data"), QString(),
            tr("Comma separated file (*.csv)"), NULL);

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);
    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn(tr("Identity"), IdentityTableModel::Name, Qt::EditRole);
	writer.addColumn(tr("Multisignature"), IdentityTableModel::Multisig, Qt::EditRole);
	writer.addColumn(tr("Expires On"), IdentityTableModel::ExpiresOn, Qt::EditRole);
	writer.addColumn(tr("Expired"), IdentityTableModel::Expired, Qt::EditRole);
	writer.addColumn(tr("Buyer Rating"), IdentityTableModel::RatingAsBuyer, IdentityTableModel::BuyerRatingRole);
	writer.addColumn(tr("Seller Rating"), IdentityTableModel::RatingAsSeller, IdentityTableModel::SellerRatingRole);
	writer.addColumn(tr("Arbiter Rating"), IdentityTableModel::RatingAsArbiter, IdentityTableModel::ArbiterRatingRole);
    if(!writer.write())
    {
		QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file: ") + filename,
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void MyIdentityListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void MyIdentityListPage::selectNewIdentity(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, IdentityTableModel::Name, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newIdentityToSelect))
    {
        // Select row of newly created identity, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newIdentityToSelect.clear();
    }
}
