#include "offerwhitelisttablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"

#include "wallet/wallet.h"
#include "base58.h"

#include <QFont>
using namespace std;

struct OfferWhitelistTableEntry
{

    QString identity;
	QString expires;
	QString discount;	

    OfferWhitelistTableEntry() {}
    OfferWhitelistTableEntry(const QString &identity, const QString &expires,const QString &discount):
        identity(identity), expires(expires),discount(discount) {}
};

struct OfferWhitelistTableEntryLessThan
{
    bool operator()(const OfferWhitelistTableEntry &a, const OfferWhitelistTableEntry &b) const
    {
        return a.identity < b.identity;
    }
    bool operator()(const OfferWhitelistTableEntry &a, const QString &b) const
    {
        return a.identity < b;
    }
    bool operator()(const QString &a, const OfferWhitelistTableEntry &b) const
    {
        return a < b.identity;
    }
};

// Private implementation
class OfferWhitelistTablePriv
{
public:
    QList<OfferWhitelistTableEntry> cachedEntryTable;
    OfferWhitelistTableModel *parent;

    OfferWhitelistTablePriv(OfferWhitelistTableModel *parent):
        parent(parent) {}


    void updateEntry(const QString &identity, const QString &expires,const QString &discount, int status)
    {
		if(!parent)
		{
			return;
		}
        // Find offer / value in model
        QList<OfferWhitelistTableEntry>::iterator lower = qLowerBound(
            cachedEntryTable.begin(), cachedEntryTable.end(), identity, OfferWhitelistTableEntryLessThan());
        QList<OfferWhitelistTableEntry>::iterator upper = qUpperBound(
            cachedEntryTable.begin(), cachedEntryTable.end(), identity, OfferWhitelistTableEntryLessThan());
        int lowerIndex = (lower - cachedEntryTable.begin());
        int upperIndex = (upper - cachedEntryTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedEntryTable.insert(lowerIndex, OfferWhitelistTableEntry(identity, expires, discount));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                break;
            }
			lower->identity = identity;
			lower->expires = expires;
			lower->discount = discount;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedEntryTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedEntryTable.size();
    }

    OfferWhitelistTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedEntryTable.size())
        {
            return &cachedEntryTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

OfferWhitelistTableModel::OfferWhitelistTableModel(WalletModel *parent) :
    QAbstractTableModel(parent)
{
    columns << tr("Identity") << tr("Discount") << tr("Expires On");
    priv = new OfferWhitelistTablePriv(this);

}

OfferWhitelistTableModel::~OfferWhitelistTableModel()
{
    delete priv;
}
int OfferWhitelistTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int OfferWhitelistTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant OfferWhitelistTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    OfferWhitelistTableEntry *rec = static_cast<OfferWhitelistTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Identity:
            return rec->identity;
        case Discount:
            return rec->discount;
        case Expires:
            return rec->expires;
        }
    }
    else if (role == IdentityRole)
    {
        return rec->identity;
    }
    return QVariant();
}

bool OfferWhitelistTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    OfferWhitelistTableEntry *rec = static_cast<OfferWhitelistTableEntry*>(index.internalPointer());

    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Identity:
            // Do nothing, if old value == new value
            if(rec->identity == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
             // Check for duplicates
            else if(lookupEntry(rec->identity) != -1)
            {
                editStatus = DUPLICATE_ENTRY;
                return false;
            }         
            break;
        case Discount:
            // Do nothing, if old value == new value
            if(rec->discount == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
           
            break;
       case Expires:
            // Do nothing, if old value == new value
            if(rec->expires == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            break;
        return true;
		}
    }
    return false;
}

QVariant OfferWhitelistTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags OfferWhitelistTableModel::flags(const QModelIndex &index) const
{
    if(!index.isValid())
        return 0;
    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    return retval;
}

QModelIndex OfferWhitelistTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    OfferWhitelistTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void OfferWhitelistTableModel::updateEntry(const QString &identity, const QString &expires,const QString &discount, int status)
{
    priv->updateEntry(identity, expires, discount, status);
}

QString OfferWhitelistTableModel::addRow(const QString &identity, const QString &expires,const QString &discount)
{
    std::string strIdentity = identity.toStdString();
    editStatus = OK;
    // Check for duplicate
    {
        if(lookupEntry(identity) != -1)
        {
            editStatus = DUPLICATE_ENTRY;
            return QString();
        }
    }

    // Add entry

    return QString::fromStdString(strIdentity);
}
void OfferWhitelistTableModel::clear()
{
	beginResetModel();
    priv->cachedEntryTable.clear();
	endResetModel();
}


int OfferWhitelistTableModel::lookupEntry(const QString &identity) const
{
    QModelIndexList lst = match(index(0, Identity, QModelIndex()),
                                Qt::EditRole, identity, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void OfferWhitelistTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
