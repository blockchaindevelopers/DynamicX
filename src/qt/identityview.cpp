/*
 * Dynamic Developers 2016
 */
#include "identityview.h"
#include "dynamicgui.h"

#include "platformstyle.h"
#include "guiutil.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "myidentitylistpage.h"
#include "identitylistpage.h"
#include "identitytablemodel.h"
#include "ui_interface.h"

#include <QAction>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QPushButton>

IdentityView::IdentityView(const PlatformStyle *platformStyle, QStackedWidget *parent):
    clientModel(0),
    walletModel(0)
{
	tabWidget = new QTabWidget();
    identityListPage = new IdentityListPage(platformStyle);
    myIdentityListPage = new MyIdentityListPage(platformStyle);
	QString theme = GUIUtil::getThemeName();
	tabWidget->addTab(myIdentityListPage, tr("My Identities"));
	tabWidget->addTab(identityListPage, tr("Search"));
	tabWidget->setTabIcon(0, platformStyle->SingleColorIcon(":/icons/" + theme + "/identity"));
	tabWidget->setTabIcon(1, platformStyle->SingleColorIcon(":/icons/" + theme + "/search"));
	parent->addWidget(tabWidget);

}

IdentityView::~IdentityView()
{
}

void IdentityView::setDynamicGUI(DynamicGUI *gui)
{
    this->gui = gui;
}

void IdentityView::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if (clientModel)
    {
       
        identityListPage->setOptionsModel(clientModel->getOptionsModel());
		myIdentityListPage->setOptionsModel(clientModel,clientModel->getOptionsModel());

    }
}

void IdentityView::setWalletModel(WalletModel *walletModel)
{

    this->walletModel = walletModel;
    if (walletModel)
    {

        identityListPage->setModel(walletModel, walletModel->getIdentityTableModelAll());
		myIdentityListPage->setModel(walletModel, walletModel->getIdentityTableModelMine());

    }
}


void IdentityView::gotoIdentityListPage()
{
	tabWidget->setCurrentWidget(identityListPage);
}
