#include <boost/assign/list_of.hpp>

#include "escrowlistpage.h"
#include "ui_escrowlistpage.h"
#include "platformstyle.h"
#include "escrowtablemodel.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "dynamicgui.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "ui_interface.h"
#include "platformstyle.h"
#include "escrowinfodialog.h"
#include "manageescrowdialog.h"
#include <QClipboard>
#include <QMessageBox>
#include <QKeyEvent>
#include <QDateTime>
#include <QMenu>
#include "main.h"
#include "rpcserver.h"

using namespace std;


extern const CRPCTable tableRPC;

EscrowListPage::EscrowListPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EscrowListPage),
    model(0),
    optionsModel(0),
	currentPage(0),
	platformStyle(platformStyle)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	if (!platformStyle->getImagesOnButtons())
	{
		ui->copyEscrow->setIcon(QIcon());
		ui->searchEscrow->setIcon(QIcon());
		ui->detailButton->setIcon(QIcon());
		ui->manageButton->setIcon(QIcon());
		ui->ackButton->setIcon(QIcon());
	}
	else
	{
		ui->copyEscrow->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/editcopy"));
		ui->searchEscrow->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/search"));
		ui->detailButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/details"));
		ui->manageButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/escrow1"));
		ui->ackButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/synced"));
	}
    ui->labelExplanation->setText(tr("Search for Dynamic Escrows."));
	
    // Context menu actions
    QAction *copyEscrowAction = new QAction(ui->copyEscrow->text(), this);
    QAction *copyOfferAction = new QAction(tr("Copy Offer ID"), this);
	QAction *detailsAction = new QAction(tr("Details"), this);
	QAction *manageAction = new QAction(tr("Manage Escrow"), this);
	QAction *ackAction = new QAction(tr("Acknowledge Payment"), this);

	connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(on_detailButton_clicked()));
    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyEscrowAction);
    contextMenu->addAction(copyOfferAction);
	contextMenu->addSeparator();
	contextMenu->addAction(detailsAction);
	contextMenu->addAction(manageAction);
	contextMenu->addAction(ackAction);

    // Connect signals for context menu actions
    connect(copyEscrowAction, SIGNAL(triggered()), this, SLOT(on_copyEscrow_clicked()));
    connect(copyOfferAction, SIGNAL(triggered()), this, SLOT(on_copyOffer_clicked()));
	connect(detailsAction, SIGNAL(triggered()), this, SLOT(on_detailButton_clicked()));
	connect(manageAction, SIGNAL(triggered()), this, SLOT(on_manageButton_clicked()));
	connect(ackAction, SIGNAL(triggered()), this, SLOT(on_ackButton_clicked()));
   
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));


	ui->lineEditEscrowSearch->setPlaceholderText(tr("Enter search term. Search for arbiter/seller or escrow GUID. Empty will search for all."));
}

EscrowListPage::~EscrowListPage()
{
    delete ui;
}
void EscrowListPage::showEvent ( QShowEvent * event )
{
    if(!walletModel) return;

}
void EscrowListPage::setModel(WalletModel* walletModel, EscrowTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    ui->tableView->setModel(model);
	ui->tableView->setSortingEnabled(false);
    // Set column widths
    ui->tableView->setColumnWidth(0, 50); //escrow id
    ui->tableView->setColumnWidth(1, 50); //time
    ui->tableView->setColumnWidth(2, 150); //seller
    ui->tableView->setColumnWidth(3, 150); //arbiter
    ui->tableView->setColumnWidth(4, 150); //buyer
    ui->tableView->setColumnWidth(5, 80); //offer
	ui->tableView->setColumnWidth(6, 250); //offer title
    ui->tableView->setColumnWidth(7, 80); //total
	ui->tableView->setColumnWidth(8, 150); //rating
    ui->tableView->setColumnWidth(9, 50); //status
	

    ui->tableView->horizontalHeader()->setStretchLastSection(true);

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));


    // Select row for newly created escrow
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)), this, SLOT(selectNewEscrow(QModelIndex,int,int)));
    selectionChanged();

}

void EscrowListPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}
void EscrowListPage::on_ackButton_clicked()
{
 	if(!model)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
    QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Escrow Acknowledgement"),
         tr("Warning: You are about to acknowledge this payment from the buyer. If you are shipping an item, please communicate a tracking number to the buyer via a Dynamic message.") + "<br><br>" + tr("Are you sure you wish to acknowledge this payment?"),
         QMessageBox::Yes|QMessageBox::Cancel,
         QMessageBox::Cancel);
    if(retval == QMessageBox::Yes)
    {
		UniValue params(UniValue::VARR);
		string strMethod = string("escrowacknowledge");
		params.push_back(escrow.toStdString());

		try {
			UniValue result = tableRPC.execute(strMethod, params);
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 1)
			{
				const UniValue& complete_value = resArray[1];
				bool bComplete = false;
				if (complete_value.isStr())
					bComplete = complete_value.get_str() == "true";
				if(!bComplete)
				{
					string hex_str = resArray[0].get_str();
					GUIUtil::setClipboard(QString::fromStdString(hex_str));
					QMessageBox::information(this, windowTitle(),
						tr("This transaction requires more signatures. Transaction hex has been copied to your clipboard for your reference. Please provide it to a signee that has not yet signed."),
							QMessageBox::Ok, QMessageBox::Ok);
				}
			}
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error acknowledging escrow payment: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception acknowledging escrow payment"),
				QMessageBox::Ok, QMessageBox::Ok);
		}
	}    
}
void EscrowListPage::on_copyEscrow_clicked()
{
   
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Escrow);
}

void EscrowListPage::on_copyOffer_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, EscrowTableModel::Offer);
}

void EscrowListPage::on_manageButton_clicked()
{
 	if(!model || !walletModel)	
		return;
	if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(selection.isEmpty())
    {
        return;
    }
	QString escrow = selection.at(0).data(EscrowTableModel::EscrowRole).toString();
	ManageEscrowDialog dlg(walletModel, escrow);   
	dlg.exec();
}
void EscrowListPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        ui->copyEscrow->setEnabled(true);
    }
    else
    {
        ui->copyEscrow->setEnabled(false);
    }
}
void EscrowListPage::keyPressEvent(QKeyEvent * event)
{
  if( event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter )
  {
	on_searchEscrow_clicked();
    event->accept();
  }
  else
    QDialog::keyPressEvent( event );
}
void EscrowListPage::on_detailButton_clicked()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        EscrowInfoDialog dlg(platformStyle, selection.at(0));
        dlg.exec();
    }
}
void EscrowListPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid()) {
        contextMenu->exec(QCursor::pos());
    }
}

void EscrowListPage::selectNewEscrow(const QModelIndex &parent, int begin, int /*end*/)
{
    QModelIndex idx = model->index(begin, EscrowTableModel::Escrow, parent);
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newEscrowToSelect))
    {
        // Select row of newly created escrow, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newEscrowToSelect.clear();
    }
}
void EscrowListPage::on_prevButton_clicked()
{
	if(pageMap.empty())
	{
		ui->nextButton->setEnabled(false);
		ui->prevButton->setEnabled(false);
		return;
	}
	currentPage--;
	const pair<string, string> &escrowPair = pageMap[currentPage];
	on_searchEscrow_clicked(escrowPair.first);
}
void EscrowListPage::on_nextButton_clicked()
{
	if(pageMap.empty())
	{
		ui->nextButton->setEnabled(false);
		ui->prevButton->setEnabled(false);
		return;
	}
	const pair<string, string> &escrowPair = pageMap[currentPage];
	currentPage++;
	on_searchEscrow_clicked(escrowPair.second);
	ui->prevButton->setEnabled(true);
}
void EscrowListPage::on_searchEscrow_clicked(string GUID)
{
    if(!walletModel) return;
	if(GUID == "")
	{
		ui->nextButton->setEnabled(false);
		ui->prevButton->setEnabled(false);
		pageMap.clear();
		currentPage = 0;
	}
       UniValue params(UniValue::VARR);
        UniValue valError;
        UniValue valResult;
        UniValue valId;
        UniValue result ;
        string strReply;
        string strError;
        string strMethod = string("escrowfilter");
		string firstEscrow = "";
		string lastEscrow = "";
		string name_str;
		string time_str;
		string seller_str;
		string arbiter_str;
		string status_str;
		string offer_str;
		string offertitle_str;
		string total_str;	
		string buyer_str;
		string rating_str;
		int unixTime;
		QDateTime dateTime;
        params.push_back(ui->lineEditEscrowSearch->text().toStdString());
		params.push_back(GUID);

        try {
            result = tableRPC.execute(strMethod, params);
        }
        catch (UniValue& objError)
        {
            strError = find_value(objError, "message").get_str();
            QMessageBox::critical(this, windowTitle(),
            tr("Error searching Escrow: ") + QString::fromStdString(strError),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
        catch(std::exception& e)
        {
            QMessageBox::critical(this, windowTitle(),
                tr("General exception when searching escrow"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
		if (result.type() == UniValue::VARR)
			{
				this->model->clear();
			
			  const UniValue &arr = result.get_array();
			  if(arr.size() >= 25)
				  ui->nextButton->setEnabled(true);
			  else
				  ui->nextButton->setEnabled(false);
			  if(currentPage <= 0)
				  ui->prevButton->setEnabled(false);
			  else
				  ui->prevButton->setEnabled(true);
		      for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";
				time_str = "";
				seller_str = "";
				arbiter_str = "";
				status_str = "";
				offer_str = "";
				offertitle_str = "";
				total_str = "";
				buyer_str = "";
				rating_str = "";
				
				const UniValue& name_value = find_value(o, "escrow");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();
				if(firstEscrow == "")
					firstEscrow = name_str;
				lastEscrow = name_str;
				const UniValue& time_value = find_value(o, "time");
				if (time_value.type() == UniValue::VSTR)
					time_str = time_value.get_str();
				const UniValue& seller_value = find_value(o, "seller");
				if (seller_value.type() == UniValue::VSTR)
					seller_str = seller_value.get_str();
				const UniValue& arbiter_value = find_value(o, "arbiter");
				if (arbiter_value.type() == UniValue::VSTR)
					arbiter_str = arbiter_value.get_str();
				const UniValue& buyer_value = find_value(o, "buyer");
				if (buyer_value.type() == UniValue::VSTR)
					buyer_str = buyer_value.get_str();
				const UniValue& offer_value = find_value(o, "offer");
				if (offer_value.type() == UniValue::VSTR)
					offer_str = offer_value.get_str();
				const UniValue& offertitle_value = find_value(o, "offertitle");
				if (offertitle_value.type() == UniValue::VSTR)
					offertitle_str = offertitle_value.get_str();
				string currency_str = "";
				const UniValue& currency_value = find_value(o, "currency");
				if (currency_value.type() == UniValue::VSTR)
					currency_str = currency_value.get_str();
				const UniValue& total_value = find_value(o, "total");
				if (total_value.type() == UniValue::VSTR)
					total_str = total_value.get_str() + string(" ") + currency_str;
				const UniValue& status_value = find_value(o, "status");
				if (status_value.type() == UniValue::VSTR)
					status_str = status_value.get_str();
				const UniValue& rating_value = find_value(o, "avg_rating_display");
				if (rating_value.type() == UniValue::VSTR)
					rating_str = rating_value.get_str();


				unixTime = atoi(time_str.c_str());
				dateTime.setTime_t(unixTime);
				time_str = dateTime.toString().toStdString();

				model->addRow(QString::fromStdString(name_str), unixTime, QString::fromStdString(time_str),
						QString::fromStdString(seller_str),
						QString::fromStdString(arbiter_str),
						QString::fromStdString(offer_str),
						QString::fromStdString(offertitle_str),
						QString::fromStdString(total_str),
						QString::fromStdString(rating_str),
						QString::fromStdString(status_str),
						QString::fromStdString(buyer_str));
					this->model->updateEntry(QString::fromStdString(name_str), unixTime, QString::fromStdString(time_str),
						QString::fromStdString(seller_str),
						QString::fromStdString(arbiter_str),
						QString::fromStdString(offer_str),
						QString::fromStdString(offertitle_str),
						QString::fromStdString(total_str),
						QString::fromStdString(rating_str),
						QString::fromStdString(status_str), 
						QString::fromStdString(buyer_str), AllEscrow, CT_NEW);	
			  }

  		  pageMap[currentPage] = make_pair(firstEscrow, lastEscrow);  
		  ui->labelPage->setText(tr("Current Page: ") + QString("<b>%1</b>").arg(currentPage+1));
         }   
        else
        {
            QMessageBox::critical(this, windowTitle(),
                tr("Error: Invalid response from escrowfilter command"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }

}
