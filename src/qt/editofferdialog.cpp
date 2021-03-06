#include "editofferdialog.h"
#include "ui_editofferdialog.h"

#include "offertablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "dynamicgui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QMessageBox>
#include <QStringList>
#include "rpcserver.h"
#include "main.h"
#include "qcomboboxdelegate.h"
#include <QSettings>
#include <QStandardItemModel>
#include <QCheckBox>
#include <boost/algorithm/string.hpp>
using namespace std;

extern const CRPCTable tableRPC;
string getCurrencyToDYNFromIdentity(const vector<unsigned char> &vchIdentityPeg, const vector<unsigned char> &vchCurrency, double &nFee, const unsigned int &nHeightToFind, vector<string>& rateList, int &precision, int &nFeePerByte, float &fEscrowFee);
extern bool getCategoryList(vector<string>& categoryList);
extern vector<unsigned char> vchFromString(const std::string &str);
EditOfferDialog::EditOfferDialog(Mode mode,  const QString &strOffer,  const QString &strCert,  const QString &strIdentity, const QString &strCategory, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditOfferDialog), mapper(0), mode(mode), model(0)
{
	overrideSafeSearch = false;
    ui->setupUi(this);
	ui->identityPegEdit->setEnabled(false);
	
	ui->identityPegDisclaimer->setText(QString("<font color='blue'>") + tr("You may change the identity rate peg through your identity settings") + QString("</font>"));
	ui->privateDisclaimer->setText(QString("<font color='blue'>") + tr("Choose if you would like the offer to be private or publicly listed on the marketplace") + QString("</font>"));
	ui->offerLabel->setVisible(true);
	ui->offerEdit->setVisible(true);
	ui->offerEdit->setEnabled(false);
	ui->rootOfferEdit->setEnabled(false);
	ui->identityEdit->setEnabled(true);
	ui->commissionLabel->setVisible(false);
	ui->commissionEdit->setVisible(false);
	ui->commissionDisclaimer->setVisible(false);
	ui->offerEdit->setEnabled(false);
	ui->rootOfferLabel->setVisible(false);
	ui->rootOfferEdit->setVisible(false);
	ui->privateEdit->setEnabled(true);
	ui->currencyEdit->addItem(QString("USD"));

	ui->geolocationDisclaimer->setText(QString("<font color='blue'>") + tr("If you wish you may enter your merchant geolocation (latitude and longitude coordinates) to help track shipping rates and other logistics information") + QString("</font>"));
	ui->currencyDisclaimer->setText(QString("<font color='blue'>") + tr("You will receive payment in Dynamic equivalent to the Market-value of the currency you have selected") + QString("</font>"));
	ui->paymentOptionsDisclaimer->setText(QString("<font color='blue'>") + tr("Choose which crypto-currency you want to allow as a payment method for this offer. Your choices are any combination of DYN, BTC or SEQ. An example setting for all three: 'DYN+BTC+SEQ'. For DYN and SEQ: 'DYN+SEQ'. Please note that in order to spend coins paid to you via Dynamic Marketplace, you will need to import your Dynamic private key in external wallet(s) if BTC or SEQ are chosen.") + QString("</font>"));
	cert = strCert;
	identity = strIdentity;
	ui->certEdit->clear();
	ui->certEdit->addItem(tr("Select Certificate (optional)"));
	loadIdentities();
	connect(ui->identityEdit,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(identityChanged(const QString&)));
	loadCategories();
	ui->descriptionEdit->setStyleSheet("color: rgb(0, 0, 0); background-color: rgb(255, 255, 255)");
	connect(ui->certEdit, SIGNAL(currentIndexChanged(int)), this, SLOT(certChanged(int)));
    QSettings settings;
	QString defaultPegIdentity, defaultOfferIdentity;
	int identityIndex;
	switch(mode)
    {
    case NewOffer:
		ui->offerLabel->setVisible(false);
		ui->offerEdit->setVisible(false);
		defaultPegIdentity = settings.value("defaultPegIdentity", "").toString();
		ui->identityPegEdit->setText(defaultPegIdentity);
		defaultOfferIdentity = settings.value("defaultIdentity", "").toString();
		identityIndex = ui->identityEdit->findText(defaultOfferIdentity);
		if(identityIndex >= 0)
			ui->identityEdit->setCurrentIndex(identityIndex);
		
		on_identityPegEdit_editingFinished();
        setWindowTitle(tr("New Offer"));
        break;
    case EditOffer:
        setWindowTitle(tr("Edit Offer"));
		 if(isLinkedOffer(strOffer))
		 {
			setWindowTitle(tr("Edit Linked Offer"));
			ui->priceEdit->setEnabled(false);
			ui->qtyEdit->setEnabled(false);
			ui->certEdit->setEnabled(false);
			ui->rootOfferLabel->setVisible(true);
			ui->rootOfferEdit->setVisible(true);
			ui->rootOfferEdit->setText(strOffer);
			ui->commissionLabel->setVisible(true);
			ui->commissionEdit->setVisible(true);
			ui->commissionDisclaimer->setVisible(true);
			ui->commissionEdit->setText(commission);
			ui->commissionDisclaimer->setText(QString("<font color='blue'>") + tr("Enter the 'percentage' amount(without the % sign) that you would like to mark-up the price to") + QString("</font>"));
		 }
        break;
    case NewCertOffer:
		ui->identityEdit->setEnabled(false);
		ui->offerLabel->setVisible(false);
		defaultPegIdentity = settings.value("defaultPegIdentity", "").toString();
		ui->identityPegEdit->setText(defaultPegIdentity);
		on_identityPegEdit_editingFinished();
		ui->offerEdit->setVisible(false);
        setWindowTitle(tr("New Offer(Certificate)"));
		ui->qtyEdit->setText("1");
		ui->qtyEdit->setEnabled(false);
		
		int index = ui->categoryEdit->findText(strCategory);
		if(index == -1)
			index = ui->categoryEdit->findText(tr("certificates"));
		if(index >= 0)
			ui->categoryEdit->setCurrentIndex(index);

        break;
	}
	identityChanged(ui->identityEdit->currentText());
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}
bool EditOfferDialog::isLinkedOffer(const QString& offerGUID)
{
	string strError;
	string strMethod = string("offerinfo");
	UniValue params(UniValue::VARR);
	UniValue result(UniValue::VOBJ);
	params.push_back(offerGUID.toStdString());
	QString sellerStr;
    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			
			QString linkedStr = QString::fromStdString(find_value(result.get_obj(), "offerlink").get_str());
			if(linkedStr == QString("true"))
			{
				commission = QString::fromStdString(find_value(result.get_obj(), "commission").get_str());
				return true;
			}
		}
	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
				tr("Could not find this offer, please ensure offer has been confirmed by the blockchain"),
				QMessageBox::Ok, QMessageBox::Ok);

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to locate this offer, please ensure offer has been confirmed by the blockchain: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}

	

	return false;


}
void EditOfferDialog::on_identityPegEdit_editingFinished()
{
	double nFee;
	vector<string> rateList;
	int precision;
	int nFeePerByte;
	float fEscrowFee;
	QString currentCurrency = ui->currencyEdit->currentText();
	if(getCurrencyToDYNFromIdentity(vchFromString(ui->identityPegEdit->text().toStdString()), vchFromString(currentCurrency.toStdString()), nFee, chainActive.Tip()->nHeight, rateList, precision, nFeePerByte, fEscrowFee) == "1")
	{
		QMessageBox::warning(this, windowTitle(),
			tr("Warning: identity peg not found. No currency information available for ") + ui->currencyEdit->currentText(),
				QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	ui->currencyEdit->clear();
	for(int i =0;i<rateList.size();i++)
	{
		ui->currencyEdit->addItem(QString::fromStdString(rateList[i]));
	}
	int currencyIndex = ui->currencyEdit->findText(currentCurrency);
	if(currencyIndex >= 0)
		ui->currencyEdit->setCurrentIndex(currencyIndex);

}
void EditOfferDialog::setOfferNotSafeBecauseOfIdentity(const QString &identity)
{
	ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText("No"));
	ui->safeSearchEdit->setEnabled(false);
	ui->safeSearchDisclaimer->setText(QString("<font color='red'><b>%1</b>").arg(identity) + tr(" is not safe to search so this setting can only be set to 'No'") + QString("</font>"));
	overrideSafeSearch = true;
}
void EditOfferDialog::resetSafeSearch()
{
	ui->safeSearchEdit->setEnabled(true);
	ui->safeSearchDisclaimer->setText(QString("<font color='blue'>") + tr("Is this offer safe to search? Anything that can be considered offensive to someone should be set to 'No' here. If you do create an offer that is offensive and do not set this option to 'No' your offer will be banned aswell as possibly your store identity!") + QString("</font>"));
		
	
}
void EditOfferDialog::identityChanged(const QString& identity)
{
	string strMethod = string("identityinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(identity.toStdString());
	UniValue result ;
	string name_str;
	string identity_peg;
	int expired = 0;
	bool safeSearch;
	int safetyLevel;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			name_str = "";
			safeSearch = false;
			expired = safetyLevel = 0;
			const UniValue& o = result.get_obj();
			name_str = identity_peg = "";
			safeSearch = false;
			expired = safetyLevel = 0;


	
			const UniValue& name_value = find_value(o, "name");
			if (name_value.type() == UniValue::VSTR)
				name_str = name_value.get_str();		
			const UniValue& expired_value = find_value(o, "expired");
			if (expired_value.type() == UniValue::VNUM)
				expired = expired_value.get_int();
			const UniValue& ss_value = find_value(o, "safesearch");
			if (ss_value.type() == UniValue::VSTR)
				safeSearch = ss_value.get_str() == "Yes";	
			const UniValue& identity_peg_value = find_value(o, "identity_peg");
			if (identity_peg_value.type() == UniValue::VSTR)
				identity_peg = identity_peg_value.get_str();	
			
			const UniValue& sl_value = find_value(o, "safetylevel");
			if (sl_value.type() == UniValue::VNUM)
				safetyLevel = sl_value.get_int();
			if(!safeSearch || safetyLevel > 0)
			{
				setOfferNotSafeBecauseOfIdentity(QString::fromStdString(name_str));
			}
			else
				resetSafeSearch();

			if(expired != 0)
			{
				ui->identityDisclaimer->setText(QString("<font color='red'>") + tr("This identity has expired, please choose another one") + QString("</font>"));				
			}
			else
				ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("Select an identity to own this offer") + QString("</font>"));		
			ui->identityPegEdit->setText(QString::fromStdString(identity_peg));
			on_identityPegEdit_editingFinished();
		}
		else
		{
			resetSafeSearch();
			ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("Select an identity to own this offer") + QString("</font>"));
		}
	}
	catch (UniValue& objError)
	{
		resetSafeSearch();
		ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("Select an identity to own this offer") + QString("</font>"));
	}
	catch(std::exception& e)
	{
		resetSafeSearch();
		ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("Select an identity to own this offer") + QString("</font>"));
	}  
	loadCerts(identity);
}
void EditOfferDialog::certChanged(int index)
{
	if(index > 0)
	{
		ui->qtyEdit->setText("1");
		ui->qtyEdit->setEnabled(false);
		ui->identityEdit->setEnabled(false);
		ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("This will automatically use the identity which owns the certificate you are selling") + QString("</font>"));
	}
	else if(index == 0)
	{
		ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("Select an identity to own this offer") + QString("</font>"));
		ui->qtyEdit->setEnabled(true);
		ui->identityEdit->setEnabled(true);
	}
}

void EditOfferDialog::addParentItem( QStandardItemModel * model, const QString& text, const QVariant& data )
{
	QList<QStandardItem*> lst = model->findItems(text,Qt::MatchExactly);
	for(unsigned int i=0; i<lst.count(); ++i )
	{ 
		if(lst[i]->data(Qt::UserRole) == data)
			return;
	}
    QStandardItem* item = new QStandardItem( text );
	item->setData( data, Qt::UserRole );
    item->setData( "parent", Qt::AccessibleDescriptionRole );
    QFont font = item->font();
    font.setBold( true );
    item->setFont( font );
    model->appendRow( item );
}

void EditOfferDialog::addChildItem( QStandardItemModel * model, const QString& text, const QVariant& data )
{
	QList<QStandardItem*> lst = model->findItems(text,Qt::MatchExactly);
	for(unsigned int i=0; i<lst.count(); ++i )
	{ 
		if(lst[i]->data(Qt::UserRole) == data)
			return;
	}

    QStandardItem* item = new QStandardItem( text + QString( 4, QChar( ' ' ) ) );
    item->setData( data, Qt::UserRole );
    item->setData( "child", Qt::AccessibleDescriptionRole );
    model->appendRow( item );
}
void EditOfferDialog::loadCategories()
{
    QStandardItemModel * model = new QStandardItemModel;
	vector<string> categoryList;
	if(!getCategoryList(categoryList))
	{
		return;
	}
	for(unsigned int i = 0;i< categoryList.size(); i++)
	{
		vector<string> categories;
		boost::split(categories,categoryList[i],boost::is_any_of(">"));
		if(categories.size() > 0)
		{
			if(categories.size() <= 2)
			{
				for(unsigned int j = 0;j< categories.size(); j++)
				{
					boost::algorithm::trim(categories[j]);
					// only support 2 levels in qt GUI for categories
					if(j == 0)
					{
						addParentItem(model, QString::fromStdString(categories[0]), QVariant(QString::fromStdString(categories[0])));
					}
					else if(j == 1)
					{
						addChildItem(model, QString::fromStdString(categories[1]), QVariant(QString::fromStdString(categoryList[i])));
					}
				}
			}
		}
		else
		{
			addParentItem(model, QString::fromStdString(categoryList[i]), QVariant(QString::fromStdString(categoryList[i])));
		}
	}
    ui->categoryEdit->setModel(model);
    ui->categoryEdit->setItemDelegate(new ComboBoxDelegate);
}
void EditOfferDialog::loadCerts(const QString &identity)
{
	ui->certEdit->clear();
	ui->certEdit->addItem(tr("Select Certificate (optional)"));
	string strMethod = string("certlist");
    UniValue params(UniValue::VARR); 
	params.push_back(identity.toStdString());
	UniValue result;
	string name_str;
	string title_str;
	string identity_str;
	int expired = 0;
	
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			title_str = "";
			identity_str = "";
			expired = 0;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";

				expired = 0;


		
				const UniValue& name_value = find_value(o, "cert");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();
				const UniValue& title_value = find_value(o, "title");
				if (title_value.type() == UniValue::VSTR)
					title_str = title_value.get_str();	
				const UniValue& identity_value = find_value(o, "identity");
				if (identity_value.type() == UniValue::VSTR)
					identity_str = identity_value.get_str();	
				const UniValue& expired_value = find_value(o, "expired");
				if (expired_value.type() == UniValue::VNUM)
					expired = expired_value.get_int();
				
				if(expired == 0)
				{
					QString name = QString::fromStdString(name_str);
					QString title = QString::fromStdString(title_str);
					QString identity = QString::fromStdString(identity_str);
					QString certText = name + " - " + title;
					ui->certEdit->addItem(certText,name);
					if(name == cert)
					{
						int index = ui->certEdit->findData(name);
						if ( index != -1 ) 						
						    ui->certEdit->setCurrentIndex(index);
						
						index = ui->identityEdit->findData(identity);
						if ( index != -1 ) 
						{
						    ui->identityEdit->setCurrentIndex(index);
							ui->identityDisclaimer->setText(QString("<font color='blue'>") + tr("This will automatically use the identity which owns the certificate you are selling") + QString("</font>"));
						}
						
					}
				}
				
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh cert list: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the cert list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
void EditOfferDialog::loadIdentities()
{
	ui->identityEdit->clear();
	string strMethod = string("identitylist");
    UniValue params(UniValue::VARR); 
	UniValue result ;
	string name_str;
	int expired = 0;
	bool safeSearch;
	int safetyLevel;
	try {
		result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VARR)
		{
			name_str = "";
			safeSearch = false;
			expired = safetyLevel = 0;


	
			const UniValue &arr = result.get_array();
		    for (unsigned int idx = 0; idx < arr.size(); idx++) {
			    const UniValue& input = arr[idx];
				if (input.type() != UniValue::VOBJ)
					continue;
				const UniValue& o = input.get_obj();
				name_str = "";
				safeSearch = false;
				expired = safetyLevel = 0;


		
				const UniValue& name_value = find_value(o, "name");
				if (name_value.type() == UniValue::VSTR)
					name_str = name_value.get_str();		
				const UniValue& expired_value = find_value(o, "expired");
				if (expired_value.type() == UniValue::VNUM)
					expired = expired_value.get_int();
				const UniValue& ss_value = find_value(o, "safesearch");
				if (ss_value.type() == UniValue::VSTR)
					safeSearch = ss_value.get_str() == "Yes";	
				const UniValue& sl_value = find_value(o, "safetylevel");
				if (sl_value.type() == UniValue::VNUM)
					safetyLevel = sl_value.get_int();
				if(!safeSearch || safetyLevel > 0)
				{
					setOfferNotSafeBecauseOfIdentity(QString::fromStdString(name_str));
				}				
				if(expired == 0)
				{
					QString name = QString::fromStdString(name_str);
					ui->identityEdit->addItem(name, name);		
					if(name == identity)
					{
						int index = ui->identityEdit->findData(identity);
						if ( index != -1 ) 
						{
							ui->identityEdit->setCurrentIndex(index);
						}
					}
				}
				
			}
		}
	}
	catch (UniValue& objError)
	{
		string strError = find_value(objError, "message").get_str();
		QMessageBox::critical(this, windowTitle(),
			tr("Could not refresh identity list: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to refresh the identity list: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
	}         
 
}
EditOfferDialog::~EditOfferDialog()
{
    delete ui;
}

void EditOfferDialog::setModel(WalletModel* walletModel, OfferTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->offerEdit, OfferTableModel::Name);
	mapper->addMapping(ui->certEdit, OfferTableModel::Cert);
    mapper->addMapping(ui->nameEdit, OfferTableModel::Title);
    mapper->addMapping(ui->priceEdit, OfferTableModel::Price);
	mapper->addMapping(ui->qtyEdit, OfferTableModel::Qty);	
	mapper->addMapping(ui->descriptionEdit, OfferTableModel::Description);		
	mapper->addMapping(ui->identityPegEdit, OfferTableModel::IdentityPeg);	
	mapper->addMapping(ui->geoLocationEdit, OfferTableModel::GeoLocation);
    mapper->addMapping(ui->categoryEdit, OfferTableModel::Category);
	mapper->addMapping(ui->paymentOptionsEdit, OfferTableModel::PaymentOptions);
}

void EditOfferDialog::loadRow(int row)
{
	const QModelIndex tmpIndex;
	if(model)
	{
		mapper->setCurrentIndex(row);
		QModelIndex indexCurrency = model->index(row, OfferTableModel::Currency, tmpIndex);
		QModelIndex indexPrivate = model->index(row, OfferTableModel::Private, tmpIndex);	
		QModelIndex indexIdentity = model->index(row, OfferTableModel::Identity, tmpIndex);
		QModelIndex indexQty = model->index(row, OfferTableModel::Qty, tmpIndex);
		QModelIndex indexSafeSearch = model->index(row, OfferTableModel::SafeSearch, tmpIndex);
		QModelIndex indexCategory = model->index(row, OfferTableModel::Category, tmpIndex);
		QModelIndex indexExpired = model->index(row, OfferTableModel::Expired, tmpIndex);
		if(indexExpired.isValid())
		{
			expiredStr = indexExpired.data(OfferTableModel::ExpiredRole).toString();
		}
		if(indexPrivate.isValid())
		{
			QString privateStr = indexPrivate.data(OfferTableModel::PrivateRole).toString();
			ui->privateEdit->setCurrentIndex(ui->privateEdit->findText(privateStr));
		}
		if(indexCurrency.isValid())
		{
			QString currencyStr = indexCurrency.data(OfferTableModel::CurrencyRole).toString();
			ui->currencyEdit->setCurrentIndex(ui->currencyEdit->findText(currencyStr));
			on_identityPegEdit_editingFinished();
		}
		if(indexSafeSearch.isValid() && !overrideSafeSearch)
		{
			QString safeSearchStr = indexSafeSearch.data(OfferTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
		if(indexCategory.isValid())
		{
			QString categoryStr = indexCategory.data(OfferTableModel::CategoryRole).toString();
			int index = ui->categoryEdit->findData(QVariant(categoryStr));
			if ( index != -1 ) 
			{ 
				ui->categoryEdit->setCurrentIndex(index);
			}
		}
		if(indexIdentity.isValid())
		{
			QString identityStr = indexIdentity.data(OfferTableModel::IdentityRole).toString();
			int indexInComboBox = ui->identityEdit->findText(identityStr);
			if(indexInComboBox < 0)
				indexInComboBox = 0;
			ui->identityEdit->setCurrentIndex(indexInComboBox);
		}
		if(indexQty.isValid())
		{
			QString qtyStr = indexQty.data(OfferTableModel::QtyRole).toString();
			if(qtyStr == tr("unlimited"))
				ui->qtyEdit->setText("-1");
			else
				ui->qtyEdit->setText(qtyStr);
		}
	}
}

bool EditOfferDialog::saveCurrentRow()
{

    if(!walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		if(model)
			model->editStatus = OfferTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	if(expiredStr == "Expired")
	{
        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Offer Renewal"),
                 tr("Warning: This offer is already expired!") + "<br><br>" + tr("Do you want to create a new one with the same information?"),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
        if(retval == QMessageBox::Cancel)
			return false;
		mode = NewOffer;
	}
	QString defaultPegIdentity;
	QVariant currentCategory;
	QSettings settings;
	UniValue params(UniValue::VARR);
	string strMethod;
    switch(mode)
    {
    case NewOffer:
	case NewCertOffer:
        if (ui->nameEdit->text().trimmed().isEmpty()) {
            ui->nameEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Offer not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		defaultPegIdentity = settings.value("defaultPegIdentity", "").toString();
		 if (ui->identityPegEdit->text() != defaultPegIdentity) {
			QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Identity Peg"),
                 tr("Warning: Are you sure you wish to choose this identity as your offer peg? By default the system peg is") + QString(" <b>%1</b>").arg(defaultPegIdentity),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
			if(retval == QMessageBox::Cancel)
				return false;
		}
		strMethod = string("offernew");
		params.push_back(ui->identityEdit->currentText().toStdString());
		currentCategory = ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole);
		if(ui->categoryEdit->currentIndex() > 0 &&  currentCategory != QVariant::Invalid)
			params.push_back(currentCategory.toString().toStdString());
		else
			params.push_back(ui->categoryEdit->currentText().toStdString());
		params.push_back(ui->nameEdit->text().toStdString());
		params.push_back(ui->qtyEdit->text().toStdString());
		params.push_back(ui->priceEdit->text().toStdString());
		params.push_back(ui->descriptionEdit->toPlainText().toStdString());
		params.push_back(ui->currencyEdit->currentText().toStdString());
		if(ui->certEdit->currentIndex() > 0)
		{
			params.push_back(ui->certEdit->itemData(ui->certEdit->currentIndex()).toString().toStdString());
		}
		else
		{
			params.push_back("nocert");
		}
		params.push_back(ui->paymentOptionsEdit->text().toStdString());
		params.push_back(ui->geoLocationEdit->text().toStdString());
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		params.push_back(ui->privateEdit->currentText() == QString("Yes")? "1": "0");
		try {
            UniValue result = tableRPC.execute(strMethod, params);
			const UniValue &arr = result.get_array();
			string strResult = arr[0].get_str();
			offer = ui->nameEdit->text();
			const UniValue& resArray = result.get_array();
			if(resArray.size() > 2)
			{
				const UniValue& complete_value = resArray[2];
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
					return true;
				}
			}
			
		}
		catch (UniValue& objError)
		{
			string strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error creating new Offer: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Offer: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditOffer:
		defaultPegIdentity = settings.value("defaultPegIdentity", "").toString();
		 if (ui->identityPegEdit->text() != defaultPegIdentity) {
			QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Identity Peg"),
                 tr("Warning: Are you sure you wish to choose this identity as your offer peg? By default the system peg is") + QString(" <b>%1</b>").arg(defaultPegIdentity),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
			if(retval == QMessageBox::Cancel)
				return false;
		}
        if(mapper->submit())
        {
			strMethod = string("offerupdate");
			params.push_back(ui->identityEdit->currentText().toStdString());
			params.push_back(ui->offerEdit->text().toStdString());
			currentCategory = ui->categoryEdit->itemData(ui->categoryEdit->currentIndex(), Qt::UserRole);
			if(ui->categoryEdit->currentIndex() > 0 &&  currentCategory != QVariant::Invalid)
				params.push_back(currentCategory.toString().toStdString());
			else
				params.push_back(ui->categoryEdit->currentText().toStdString());
			params.push_back(ui->nameEdit->text().toStdString());
			params.push_back(ui->qtyEdit->text().toStdString());
			params.push_back(ui->priceEdit->text().toStdString());
			params.push_back(ui->descriptionEdit->toPlainText().toStdString());
			params.push_back(ui->currencyEdit->currentText().toStdString());
			params.push_back(ui->privateEdit->currentText() == QString("Yes")? "1": "0");
			if(ui->certEdit->currentIndex() > 0)
			{
				params.push_back(ui->certEdit->itemData(ui->certEdit->currentIndex()).toString().toStdString());
			}
			else
			{
				params.push_back("nocert");
			}

			params.push_back(ui->geoLocationEdit->text().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());
			params.push_back(ui->commissionEdit->text().toStdString());
			params.push_back(ui->paymentOptionsEdit->text().toStdString());


			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
					offer = ui->nameEdit->text() + ui->offerEdit->text();

				}
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
						return true;
					}
				}
			}
			catch (UniValue& objError)
			{
				string strError = find_value(objError, "message").get_str();
				QMessageBox::critical(this, windowTitle(),
				tr("Error updating Offer: ") + QString::fromStdString(strError),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Offer: ") + QString::fromStdString(e.what()),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !offer.isEmpty();
}
void EditOfferDialog::on_cancelButton_clicked()
{
    reject();
}
void EditOfferDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EditOfferDialog::accept()
{
    if(!saveCurrentRow())
    {
		if(model)
		{
			switch(model->getEditStatus())
			{
			case OfferTableModel::OK:
				// Failed with unknown reason. Just reject.
				break;
			case OfferTableModel::NO_CHANGES:
				// No changes were made during edit operation. Just reject.
				break;
			case OfferTableModel::INVALID_OFFER:
				QMessageBox::warning(this, windowTitle(),
					tr("The entered offer is not a valid Dynamic offer"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			case OfferTableModel::WALLET_UNLOCK_FAILURE:
				QMessageBox::critical(this, windowTitle(),
					tr("Could not unlock wallet."),
					QMessageBox::Ok, QMessageBox::Ok);
				break;

			}
			return;
		}
		return;
    }
    QDialog::accept();
}

QString EditOfferDialog::getOffer() const
{
    return offer;
}

void EditOfferDialog::setOffer(const QString &offer)
{
    this->offer = offer;
    ui->offerEdit->setText(offer);
}
