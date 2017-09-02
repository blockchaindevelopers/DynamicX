#ifndef IDENTITYTABLEMODEL_H
#define IDENTITYTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

class IdentityTablePriv;
class CWallet;
class WalletModel;
enum IdentityType {AllIdentity=0,MyIdentity};

typedef enum IdentityType IdentityModelType;
/**
   Qt model of the identity                                                                                                                                                        book in the core. This allows views to access and modify the identity book.
 */
class IdentityTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit IdentityTableModel(CWallet *wallet, WalletModel *parent = 0, IdentityModelType = AllIdentity);
    ~IdentityTableModel();

    enum ColumnIndex {
        Name = 0,   /**< identity name */
		Multisig = 1,
		ExpiresOn = 2,
		Expired = 3,
		RatingAsBuyer = 4,
		RatingAsSeller = 5,
		RatingAsArbiter = 6,
		SafeSearch = 7,
		Value = 8,  /**< Identity value */
		PrivValue = 9,
		NUMBER_OF_COLUMNS
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole, /**< Type of identity (#Send or #Receive) */
		NameRole,
		MultisigRole,
		ExpiredRole,
		SafeSearchRole,
		BuyerRatingRole,
		SellerRatingRole,
		ArbiterRatingRole
	};

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,                     /**< Everything ok */
        NO_CHANGES,             /**< No changes were made during edit operation */
        INVALID_IDENTITY,        /**< Unparseable identity */
        DUPLICATE_IDENTITY,      /**< Identity already in identity book */
        WALLET_UNLOCK_FAILURE  /**< Wallet could not be unlocked */
    };

    static const QString Identity;      /**< Specifies send identity */

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex &index, const QVariant &value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex &parent) const;
    
    Qt::ItemFlags flags(const QModelIndex &index) const;
    /*@}*/

    /* Add an identity to the model.
       Returns the added identity on success, and an empty string otherwise.
     */
    QString addRow(const QString &type, const QString &identity, const QString &multisig,const QString &value, const QString &privvalue, const QString &expires_on, const QString &expired, const QString &safesearch,const QString &buyer_rating, const QString &seller_rating, const QString &arbiter_rating);

    /* Look up row index of an identity in the model.
       Return -1 if not found.
     */
    int lookupIdentity(const QString &identity) const;
	void clear();
	void refreshIdentityTable();
    EditStatus getEditStatus() const { return editStatus; }
	EditStatus editStatus;
private:
    WalletModel *walletModel;
    CWallet *wallet;
    IdentityTablePriv *priv;
    QStringList columns;
    
	IdentityModelType modelType;
    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

public Q_SLOTS:
    /* Update identity list from core.
     */
    void updateEntry(const QString &identity, const QString &multisig,const QString &value, const QString &privvalue, const QString &expires_on, const QString &expired, const QString &safesearch, const QString &buyer_rating, const QString &seller_rating, const QString &arbiter_rating, IdentityModelType type, int status);

    friend class IdentityTablePriv;
};

#endif // IDENTITYTABLEMODEL_H
