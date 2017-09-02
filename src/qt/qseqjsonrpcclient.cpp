
#include "qseqjsonrpcclient.h"
#include <QSettings>

SeqRpcClient::SeqRpcClient(const QString& seqEndPoint, const QString& seqRPCLogin, const QString& seqRPCPassword)
{
	QSettings settings;
	m_client.setEndpoint(seqEndPoint.size() > 0? seqEndPoint : settings.value("seqEndPoint", "").toString());
	m_client.setUsername(seqRPCLogin.size() > 0? seqRPCLogin : settings.value("seqRPCLogin", "").toString());
	m_client.setPassword(seqRPCPassword.size() > 0? seqRPCPassword : settings.value("seqRPCPassword", "").toString());
}
void SeqRpcClient::sendRequest(QNetworkAccessManager *nam, const QString &request, const QString &param)
{
	m_client.sendRequest(nam, request, param);
}
void SeqRpcClient::sendRawTxRequest(QNetworkAccessManager *nam, const QString &param)
{
	m_client.sendRequest(nam, "getrawtransaction", param, "1");
}
SeqRpcClient::~SeqRpcClient()
{
}
