/*
 * Dynamic Developers 2015
 */
#include <boost/assign/list_of.hpp>
#include "mywhitelistofferdialog.h"
#include "ui_mywhitelistofferdialog.h"
#include "offertablemodel.h"
#include "myofferwhitelisttablemodel.h"
#include "walletmodel.h"
#include "dynamicgui.h"
#include "platformstyle.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "ui_interface.h"
#include <QTableView>
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QModelIndex>
#include <QMenu>
#include <QItemSelection>
#include "rpcserver.h"
#include "tinyformat.h"

using namespace std;



extern const CRPCTable tableRPC;
MyWhitelistOfferDialog::MyWhitelistOfferDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MyWhitelistOfferDialog),
    model(0)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->exportButton->setIcon(QIcon());
		ui->refreshButton->setIcon(QIcon());
	}
	else
	{
		ui->exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/export"));
		ui->refreshButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/refresh"));
	}

	
    ui->labelExplanation->setText(tr("You are an affiliate for these offers. Affiliate operations take 2-5 minutes to become active. The owner of the offer may add you as to his affiliate list and your affiliate entry will show up here."));
	
    // Context menu actions
	QAction *copyAction = new QAction(tr("Copy Identity"), this);
    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyAction);

    connect(copyAction, SIGNAL(triggered()), this, SLOT(on_copy()));


    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

	on_refreshButton_clicked();
	
}

MyWhitelistOfferDialog::~MyWhitelistOfferDialog()
{
    delete ui;
}

void MyWhitelistOfferDialog::setModel(WalletModel *walletModel)
{
	if(this->model)
		delete model;
	this->model = new MyOfferWhitelistTableModel(walletModel);
	this->walletModel = walletModel;
    if(!model) return;
    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

	ui->tableView->setModel(proxyModel);
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    // Set column widths
#if QT_VERSION < 0x050000
	ui->tableView->horizontalHeader()->setResizeMode(MyOfferWhitelistTableModel::Offer, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(MyOfferWhitelistTableModel::Identity, QHeaderView::Stretch);
	ui->tableView->horizontalHeader()->setResizeMode(MyOfferWhitelistTableModel::Expires, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setResizeMode(MyOfferWhitelistTableModel::Discount, QHeaderView::ResizeToContents);
#else
	ui->tableView->horizontalHeader()->setSectionResizeMode(MyOfferWhitelistTableModel::Offer, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(MyOfferWhitelistTableModel::Identity, QHeaderView::Stretch);
	ui->tableView->horizontalHeader()->setSectionResizeMode(MyOfferWhitelistTableModel::Expires, QHeaderView::ResizeToContents);
	ui->tableView->horizontalHeader()->setSectionResizeMode(MyOfferWhitelistTableModel::Discount, QHeaderView::ResizeToContents);
#endif


	model->clear();
}


void MyWhitelistOfferDialog::showEvent ( QShowEvent * event )
{
	on_refreshButton_clicked();
}
void MyWhitelistOfferDialog::on_copy()
{
    GUIUtil::copyEntryData(ui->tableView, MyOfferWhitelistTableModel::Identity);
}

void MyWhitelistOfferDialog::on_refreshButton_clicked()
{
	if(!model) return;
	string strError;
	string strMethod = string("identityaffiliates");
	UniValue params(UniValue::VARR);
	UniValue result;
	
	try {
		result = tableRPC.execute(strMethod, params);
		if (result.type() == UniValue::VARR)
		{
			this->model->clear();
			string offer_str = "";
			string identity_str = "";
			int64_t expires_on = 0;
			string offer_discount_percentage_str = "";
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				const UniValue& offer_value = find_value(o, "offer");
				if (offer_value.type() == UniValue::VSTR)
					offer_str = offer_value.get_str();
				const UniValue& identity_value = find_value(o, "identity");
				if (identity_value.type() == UniValue::VSTR)
					identity_str = identity_value.get_str();
				const UniValue& offer_discount_percentage_value = find_value(o, "offer_discount_percentage");
				if (offer_discount_percentage_value.type() == UniValue::VSTR)
					offer_discount_percentage_str = offer_discount_percentage_value.get_str();
				const UniValue& expires_on_value = find_value(o, "expires_on");
				if (expires_on_value.type() == UniValue::VNUM)
					expires_on = expires_on_value.get_int64();
				const QString& dateTimeString = GUIUtil::dateTimeStr(expires_on);	
				model->addRow(QString::fromStdString(offer_str), QString::fromStdString(identity_str),  dateTimeString, QString::fromStdString(offer_discount_percentage_str));
				model->updateEntry(QString::fromStdString(offer_str), QString::fromStdString(identity_str),  dateTimeString, QString::fromStdString(offer_discount_percentage_str), CT_NEW); 
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh the affiliate list: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the affiliate list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}


}


void MyWhitelistOfferDialog::on_exportButton_clicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Affiliate Data"), QString(),
            tr("Comma separated file (*.csv)"), nullptr);

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);
    // name, column, role
    writer.setModel(proxyModel);
	writer.addColumn(tr("Offer"), MyOfferWhitelistTableModel::Offer, Qt::EditRole);
	writer.addColumn(tr("Identity"), MyOfferWhitelistTableModel::Identity, Qt::EditRole);
	writer.addColumn(tr("Expires"), MyOfferWhitelistTableModel::Expires, Qt::EditRole);
	writer.addColumn(tr("Discount"), MyOfferWhitelistTableModel::Discount, Qt::EditRole);
	
    if(!writer.write())
    {
		QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file: ") + filename,
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}



void MyWhitelistOfferDialog::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}
