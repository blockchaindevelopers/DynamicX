#ifndef OFFERACCEPTDIALOGSEQ_H
#define OFFERACCEPTDIALOGSEQ_H
#include "walletmodel.h"
#include <QDialog>
#include <QImage>
#include <QLabel>
#include "amount.h"
class PlatformStyle;
class WalletModel;
QT_BEGIN_NAMESPACE
class QNetworkReply;
QT_END_NAMESPACE
namespace Ui {
    class OfferAcceptDialogSEQ;
}
class OfferAcceptDialogSEQ : public QDialog
{
    Q_OBJECT

public:
    explicit OfferAcceptDialogSEQ(WalletModel* model, const PlatformStyle *platformStyle, QString strIdentityPeg, QString identity, QString offer, QString quantity, QString notes, QString title, QString currencyCode, QString sysPrice, QString sellerIdentity, QString address, QString arbiter, QWidget *parent=0);
    ~OfferAcceptDialogSEQ();
	void CheckPaymentInSEQ();
    bool getPaymentStatus();
	void SetupQRCode(const QString&price);
	void convertAddress();
private:
	bool setupEscrowCheckboxState(bool state);
	WalletModel* walletModel;
	const PlatformStyle *platformStyle;
    Ui::OfferAcceptDialogSEQ *ui;
	SendCoinsRecipient info;
	QString quantity;
	QString notes;
	QString qstrPrice;
	QString title;
	QString offer;
	QString arbiter;
	QString acceptGuid;
	QString sellerIdentity;
	QString address;
	QString zaddress;
	QString multisigaddress;
	QString identity;
	QString m_buttonText;
	QString m_address;
	double dblPrice;
	bool offerPaid; 
	QString m_redeemScript;	
	QString priceSeq;
	qint64 m_height;

private Q_SLOTS:
	void on_cancelButton_clicked();
    void tryAcceptOffer();
	void onEscrowCheckBoxChanged(bool);
    void acceptOffer();
	void acceptEscrow();
	void openSEQWallet();
	void slotConfirmedFinished(QNetworkReply *);
	void on_escrowEdit_textChanged(const QString & text);
	
};

#endif // OFFERACCEPTDIALOGSEQ_H
