#include "editidentitydialog.h"
#include "ui_editidentitydialog.h"

#include "identitytablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "dynamicgui.h"
#include "ui_interface.h"
#include <QDataWidgetMapper>
#include <QInputDialog>
#include <QMessageBox>
#include <QSettings>
#include "rpcserver.h"
#include <QDateTime>
using namespace std;

extern const CRPCTable tableRPC;
EditIdentityDialog::EditIdentityDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditIdentityDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

	ui->transferEdit->setVisible(false);
	ui->transferLabel->setVisible(false);
	ui->identityPegDisclaimer->setText(QString("<font color='blue'>") + tr("Choose an identity which has peg information. Consumers will pay conversion amounts and network fees based on this peg.") + QString("</font>"));
	ui->expiryDisclaimer->setText(QString("<font color='blue'>") + tr("Choose a standard expiration time(in UTC) for this identity from 1 to 5 years or check the 'Use Custom Expire Time' check box to enter an expiration timestamp. It is exponentially more expensive per year, calculation is FEERATE*(2.88^years). FEERATE is the dynamic satoshi per byte fee set in the rate peg identity used for this identity.") + QString("</font>"));
	ui->transferDisclaimer->setText(QString("<font color='red'>") + tr("Warning: transferring your identity will transfer ownership all of your dynamic services that use this identity.") + QString("</font>"));
	ui->transferDisclaimer->setVisible(false);
	ui->safeSearchDisclaimer->setText(QString("<font color='blue'>") + tr("Is this identity safe to search? Anything that can be considered offensive to someone should be set to 'No' here. If you do create an identity that is offensive and do not set this option to 'No' your identity will be banned!") + QString("</font>"));
	ui->expiryEdit->clear();
	QDateTime dateTime = QDateTime::currentDateTimeUtc();	
	dateTime = dateTime.addYears(1);
	ui->expiryEdit->addItem(tr("1 Year"),QVariant(dateTime.toTime_t()));
	dateTime = dateTime.addYears(1);
	ui->expiryEdit->addItem(tr("2 Years"),QVariant(dateTime.toTime_t()));
	dateTime = dateTime.addYears(1);
	ui->expiryEdit->addItem(tr("3 Years"),QVariant(dateTime.toTime_t()));
	dateTime = dateTime.addYears(1);
	ui->expiryEdit->addItem(tr("4 Years"),QVariant(dateTime.toTime_t()));
	dateTime = dateTime.addYears(1);
	ui->expiryEdit->addItem(tr("5 Years"),QVariant(dateTime.toTime_t()));

	ui->expireTimeEdit->setText(QString::number(ui->expiryEdit->itemData(0).toInt()));
	ui->expireTimeEdit->setEnabled(false);

    ui->privateDisclaimer->setText(QString("<font color='blue'>") + tr("This is to private profile information which is encrypted and only available to you. This is useful for when sending notes to a merchant through the payment screen so you don't have to type it out everytime.") + QString("</font>"));
	ui->passwordDisclaimer->setText(QString("<font color='blue'>") + tr("Enter a password or passphrase that will be used to unlock this identity via webservices such as BlockMarket. Important: Do not forget or misplace this password, it is the lock to your identity.") + QString("</font>"));
	ui->publicDisclaimer->setText(QString("<font color='blue'>") + tr("This is public profile information that anyone on the network can see. Fill this in with things you would like others to know about you.") + QString("</font>"));
	ui->reqsigsDisclaimer->setText(QString("<font color='blue'>") + tr("The number of required signatures ensures that not one person can control this identity and anything service that this identity uses (certificates, messages, offers, escrows).") + QString("</font>"));
	ui->acceptCertTransfersDisclaimer->setText(QString("<font color='blue'>") + tr("Would you like to accept certificates transferred to this identity? Select 'Yes' otherwise if you want to block others from sending certificates to this identity select 'No'.") + QString("</font>"));	
	ui->multisigTitle->setText(QString("<font color='blue'>") + tr("Set up your multisig identity here with the required number of signatures and the identities that are capable of signing when this identity is updated. A user from this list can request an update to the identity and the other signers must sign the raw multisig transaction using the 'Sign Multisig Tx' button in order for the identity to complete the update. Services that use this identity require identity updates prior to updating those services which allows all services to benefit from identity multisig technology.") + QString("</font>"));
	ui->reqSigsEdit->setValidator( new QIntValidator(0, 50, this) );
	connect(ui->reqSigsEdit, SIGNAL(textChanged(QString)), this, SLOT(reqSigsChanged()));
	connect(ui->customExpireBox,SIGNAL(clicked(bool)),SLOT(onCustomExpireCheckBoxChanged(bool)));
	connect(ui->expiryEdit,SIGNAL(currentIndexChanged(const QString&)),this,SLOT(expiryChanged(const QString&)));
	QString defaultPegIdentity;
	QSettings settings;
	switch(mode)
    {
	case NewDataIdentity:
		break;
	case NewIdentity:
		setWindowTitle(tr("New Identity"));
		defaultPegIdentity = settings.value("defaultPegIdentity", "").toString();
		ui->identityPegEdit->setText(defaultPegIdentity);
        break;
    case EditDataIdentity:
        setWindowTitle(tr("Edit Data Identity"));
		ui->identityEdit->setEnabled(false);
        break;
    case EditIdentity:
        setWindowTitle(tr("Edit Identity"));
		ui->identityEdit->setEnabled(false);
        break;
    case TransferIdentity:
        setWindowTitle(tr("Transfer Identity"));
		ui->identityEdit->setEnabled(false);
		ui->identityPegEdit->setEnabled(false);
		ui->identityPegDisclaimer->setVisible(false);
		ui->nameEdit->setEnabled(false);
		ui->safeSearchEdit->setEnabled(false);
		ui->acceptCertTransfersEdit->setEnabled(false);
		ui->acceptCertTransfersDisclaimer->setVisible(false);
		ui->safeSearchDisclaimer->setVisible(false);
		ui->privateEdit->setEnabled(false);
		ui->privateDisclaimer->setVisible(false);
		ui->transferEdit->setVisible(true);
		ui->transferLabel->setVisible(true);
		ui->transferDisclaimer->setVisible(true);
		ui->passwordDisclaimer->setVisible(false);
		ui->passwordEdit->setEnabled(false);
		ui->EditIdentityDialogTab->setCurrentIndex(1);
        break;
    }
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditIdentityDialog::~EditIdentityDialog()
{
    delete ui;
}
void EditIdentityDialog::onCustomExpireCheckBoxChanged(bool toggled)
{
	ui->expireTimeEdit->setEnabled(toggled);
}
void EditIdentityDialog::expiryChanged(const QString& identity)
{
	ui->expireTimeEdit->setText(QString::number(ui->expiryEdit->itemData(ui->expiryEdit->currentIndex()).toInt()));
}
void EditIdentityDialog::reqSigsChanged()
{
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(QString("<font color='blue'>") + tr("This is a") + QString(" <b>%1</b> ").arg(ui->reqSigsEdit->text()) + tr("of") + QString(" <b>%1</b> ").arg(QString::number(ui->multisigList->count()+1)) + tr("multisig identity.") + QString(" <b>%1</b> ").arg(ui->identityEdit->text()) + QString("is assumed to also be a signer.") + QString("</font>"));
	}
}
void EditIdentityDialog::loadIdentityDetails()
{
	string strMethod = string("identityinfo");
    UniValue params(UniValue::VARR); 
	params.push_back(ui->identityEdit->text().toStdString());
	UniValue result ;
	try {
		result = tableRPC.execute(strMethod, params);
		if (result.type() == UniValue::VOBJ)
		{
			const UniValue& identityPegValue = find_value(result.get_obj(), "identity_peg");
			ui->identityPegEdit->setText(QString::fromStdString(identityPegValue.get_str()));
			const UniValue& acceptTransferValue = find_value(result.get_obj(), "acceptcerttransfers");
			ui->acceptCertTransfersEdit->setCurrentIndex(ui->acceptCertTransfersEdit->findText(QString::fromStdString(acceptTransferValue.get_str())));
			const UniValue& multisigValue = find_value(result.get_obj(), "multisiginfo");
			if (multisigValue.type() == UniValue::VOBJ)
			{
				const UniValue& reqsigsValue = find_value(multisigValue.get_obj(), "reqsigs");
				int reqsigs = reqsigsValue.get_int();
				ui->reqSigsEdit->setText(QString::number(reqsigs));
				const UniValue& reqsignersValue = find_value(multisigValue.get_obj(), "reqsigners");
				if (reqsignersValue.type() == UniValue::VARR)
				{
					const UniValue& reqsignersArray = reqsignersValue.get_array();
					for(unsigned int i =0;i<reqsignersArray.size();i++)
					{
						string signer = reqsignersArray[i].get_str();
						ui->multisigList->addItem(QString::fromStdString(signer));
					}
				}
			}
		}
	}
	catch (UniValue& objError)
	{
	
	}
	catch(std::exception& e)
	{

	}  
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(QString("<font color='blue'>") + tr("This is a") + QString(" <b>%1</b> ").arg(ui->reqSigsEdit->text()) + tr("of") + QString(" <b>%1</b> ").arg(QString::number(ui->multisigList->count()+1)) + tr("multisig identity.") + QString(" <b>%1</b> ").arg(ui->identityEdit->text()) + QString("is assumed to also be a signer.") + QString("</font>"));
	}
}
void EditIdentityDialog::on_cancelButton_clicked()
{
    reject();
}
void EditIdentityDialog::on_addButton_clicked()
{
	
    bool ok;
    QString text = QInputDialog::getText(this, tr("Enter an identity"),
                                         tr("Identity:"), QLineEdit::Normal,
                                         "", &ok);
    if (ok && !text.isEmpty())
	{
        ui->multisigList->addItem(text);
	}
	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(QString("<font color='blue'>") + tr("This is a") + QString(" <b>%1</b> ").arg(ui->reqSigsEdit->text()) + tr("of") + QString(" <b>%1</b> ").arg(QString::number(ui->multisigList->count()+1)) + tr("multisig identity.") + QString(" <b>%1</b> ").arg(ui->identityEdit->text()) + QString("is assumed to also be a signer.") + QString("</font>"));
	}
}
void EditIdentityDialog::on_deleteButton_clicked()
{
    QModelIndexList selected = ui->multisigList->selectionModel()->selectedIndexes();    
	for (int i = selected.count() - 1; i > -1; --i)
		ui->multisigList->model()->removeRow(selected.at(i).row());

	if(ui->multisigList->count() > 0)
	{
		ui->multisigDisclaimer->setText(QString("<font color='blue'>") + tr("This is a") + QString(" <b>%1</b> ").arg(ui->reqSigsEdit->text()) + tr("of") + QString(" <b>%1</b> ").arg(QString::number(ui->multisigList->count()+1)) + tr("multisig identity.") + QString(" <b>%1</b> ").arg(ui->identityEdit->text()) + QString("is assumed to also be a signer.") + QString("</font>"));
	}
}

void EditIdentityDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}
void EditIdentityDialog::setModel(WalletModel* walletModel, IdentityTableModel *model)
{
    this->model = model;
	this->walletModel = walletModel;
    if(!model) return;

    mapper->setModel(model);
	mapper->addMapping(ui->identityEdit, IdentityTableModel::Name);
    mapper->addMapping(ui->nameEdit, IdentityTableModel::Value);
	mapper->addMapping(ui->privateEdit, IdentityTableModel::PrivValue);
	
    
}

void EditIdentityDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
	const QModelIndex tmpIndex;
	if(model)
	{
		QModelIndex indexSafeSearch= model->index(row, IdentityTableModel::SafeSearch, tmpIndex);
		QModelIndex indexExpired = model->index(row, IdentityTableModel::Expired, tmpIndex);
		if(indexExpired.isValid())
		{
			expiredStr = indexExpired.data(IdentityTableModel::ExpiredRole).toString();
		}
		if(indexSafeSearch.isValid())
		{
			QString safeSearchStr = indexSafeSearch.data(IdentityTableModel::SafeSearchRole).toString();
			ui->safeSearchEdit->setCurrentIndex(ui->safeSearchEdit->findText(safeSearchStr));
		}
	}
	loadIdentityDetails();
}

bool EditIdentityDialog::saveCurrentRow()
{
	UniValue params(UniValue::VARR);
	UniValue arraySendParams(UniValue::VARR);
	string strMethod;
    if(!model || !walletModel) return false;
    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if(!ctx.isValid())
    {
		model->editStatus = IdentityTableModel::WALLET_UNLOCK_FAILURE;
        return false;
    }
	uint32_t expiryFiveYear = ui->expiryEdit->itemData(4).toInt();
	if(ui->expireTimeEdit->text().trimmed().toInt() > expiryFiveYear)
	{
        QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Identity with large expiration"),
                 tr("Warning: Using creating an identity expiring later than 5 years increases costs exponentially, you may spend a large amount of coins in doing so!") + "<br><br>" + tr("Are you sure you wish to continue?"),
                 QMessageBox::Yes|QMessageBox::Cancel,
                 QMessageBox::Cancel);
        if(retval == QMessageBox::Cancel)
			return false;
	}
	if(expiredStr == "Expired")
	{
		mode = NewIdentity;
	}
    switch(mode)
    {
    case NewDataIdentity:
    case NewIdentity:
        if (ui->identityEdit->text().trimmed().isEmpty()) {
            ui->identityEdit->setText("");
            QMessageBox::information(this, windowTitle(),
            tr("Empty name for Identity not allowed. Please try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }
		strMethod = string("identitynew");
		params.push_back(ui->identityPegEdit->text().trimmed().toStdString());
        params.push_back(ui->identityEdit->text().trimmed().toStdString());
		params.push_back(ui->passwordEdit->text().trimmed().toStdString());
		params.push_back(ui->nameEdit->toPlainText().toStdString());
		params.push_back(ui->privateEdit->toPlainText().toStdString());
		params.push_back(ui->safeSearchEdit->currentText().toStdString());
		params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
		params.push_back(ui->expireTimeEdit->text().trimmed().toStdString());
		if(ui->multisigList->count() > 0)
		{
			params.push_back(ui->reqSigsEdit->text().toStdString());
			for(int i = 0; i < ui->multisigList->count(); ++i)
			{
				QString str = ui->multisigList->item(i)->text();
				arraySendParams.push_back(str.toStdString());
			}
			params.push_back(arraySendParams);
		}

		try {
            UniValue result = tableRPC.execute(strMethod, params);
			const UniValue &arr = result.get_array();
			string strResult = arr[0].get_str();
			identity = ui->nameEdit->toPlainText() + ui->identityEdit->text();
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
			tr("Error creating new Identity: ") + QString::fromStdString(strError),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception creating new Identity"),
				QMessageBox::Ok, QMessageBox::Ok);
			break;
		}							

        break;
    case EditDataIdentity:
    case EditIdentity:
        if(mapper->submit())
        {
			strMethod = string("identityupdate");
			params.push_back(ui->identityPegEdit->text().trimmed().toStdString());
			params.push_back(ui->identityEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());	
			params.push_back("");
			params.push_back(ui->passwordEdit->text().toStdString());	
			params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
			params.push_back(ui->expireTimeEdit->text().trimmed().toStdString());
			if(ui->multisigList->count() > 0)
			{
				params.push_back(ui->reqSigsEdit->text().toStdString());
				for(int i = 0; i < ui->multisigList->count(); ++i)
				{
					QString str = ui->multisigList->item(i)->text();
					arraySendParams.push_back(str.toStdString());
				}
				params.push_back(arraySendParams);
			}
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{
				
					identity = ui->nameEdit->toPlainText() + ui->identityEdit->text();
						
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
				tr("Error updating Identity: ") + QString::fromStdString(strError),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("General exception updating Identity"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    case TransferIdentity:
        if(mapper->submit())
        {
			strMethod = string("identityupdate");
			params.push_back(ui->identityPegEdit->text().trimmed().toStdString());
			params.push_back(ui->identityEdit->text().toStdString());
			params.push_back(ui->nameEdit->toPlainText().toStdString());
			params.push_back(ui->privateEdit->toPlainText().toStdString());
			params.push_back(ui->safeSearchEdit->currentText().toStdString());
			params.push_back(ui->transferEdit->text().toStdString());
			params.push_back(ui->passwordEdit->text().toStdString());	
			params.push_back(ui->acceptCertTransfersEdit->currentText().toStdString());
			params.push_back(ui->expireTimeEdit->text().trimmed().toStdString());
			if(ui->multisigList->count() > 0)
			{
				params.push_back(ui->reqSigsEdit->text().toStdString());
				for(int i = 0; i < ui->multisigList->count(); ++i)
				{
					QString str = ui->multisigList->item(i)->text();
					arraySendParams.push_back(str.toStdString());
				}
				params.push_back(arraySendParams);
			}
			try {
				UniValue result = tableRPC.execute(strMethod, params);
				if (result.type() != UniValue::VNULL)
				{

					identity = ui->nameEdit->toPlainText() + ui->identityEdit->text()+ui->transferEdit->text();
						
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
                tr("Error transferring Identity: ") + QString::fromStdString(strError),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}
			catch(std::exception& e)
			{
				QMessageBox::critical(this, windowTitle(),
                    tr("General exception transferring Identity"),
					QMessageBox::Ok, QMessageBox::Ok);
				break;
			}	
        }
        break;
    }
    return !identity.isEmpty();
}

void EditIdentityDialog::accept()
{
    if(!model) return;

    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case IdentityTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        case IdentityTableModel::NO_CHANGES:
            // No changes were made during edit operation. Just reject.
            break;
        case IdentityTableModel::INVALID_IDENTITY:
            QMessageBox::warning(this, windowTitle(),
				tr("The entered identity is not a valid Dynamic identity. Identity: ") + ui->identityEdit->text(),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case IdentityTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            break;

        }
        return;
    }
    QDialog::accept();
}

QString EditIdentityDialog::getIdentity() const
{
    return identity;
}

void EditIdentityDialog::setIdentity(const QString &identity)
{
    this->identity = identity;
    ui->identityEdit->setText(identity);
}
