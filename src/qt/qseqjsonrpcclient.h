#ifndef SEQRPCCLIENT_H
#define SEQRPCCLIENT_H

#include "qjsonrpcclient.h"
QT_BEGIN_NAMESPACE
class QNetworkAccessManager;
QT_END_NAMESPACE

class SeqRpcClient
{
public:
 
    explicit SeqRpcClient(const QString& seqEndPoint="", const QString& seqRPCLogin="", const QString& seqRPCPassword="");
    ~SeqRpcClient();
	void sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param="");
	void sendRawTxRequest(QNetworkAccessManager *nam, const QString &param);
private:
	RpcClient m_client;

};

#endif // SEQRPCCLIENT_H
