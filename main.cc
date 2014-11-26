#include <unistd.h>

#include <QApplication>
#include <QDebug>
#include <QFileDialog>
#include <QKeyEvent>
#include <QLabel>
#include <QtCrypto>
#include <QTimer>
#include <QVBoxLayout>

#include "main.hh"

// RSA encryption of private messages
#include "crypto.cc"
#include "crypto.hh"

// resend block requests

PrivDialog::PrivDialog(ChatDialog* dialog, QString origin, NetSocket* sock) {
  // 'Enter' detection for text entry box.
  key = new PrivKeyEnterReceiver();
  installEventFilter(key);
  key->dialog = this;

  this->origin = origin;
  this->sock = sock;
  this->cDialog = dialog;

  setWindowTitle(origin);

  // Read-only text box where we display messages from everyone.
  // This widget expands both horizontally and vertically.
  textview = new QTextEdit(this);
  textview->setReadOnly(true);

  // Text box where we enter messages.
  textline = new QTextEdit(this);

  // Set the keyboard focus to the text-entry box.
  textline->setFocus();

  QVBoxLayout *layout = new QVBoxLayout();
  layout->addWidget(textview);
  layout->addWidget(textline);
  setLayout(layout);
}

void PrivDialog::privMsgEntered() {
  QString text = textline->toPlainText();
  if (text.length() > 0) {
    const QString trimmedText = text.trimmed().replace("\n", "");
    QVariantMap* map = sock->makeMyRumorMap(&trimmedText, &origin, true);
    Destination* dest = sock->routingTable->value(origin);
    Peer peer;
    peer.IP = dest->IP;
    peer.port = dest->port;
    sock->sendMap(map, &peer);

    textview->append(trimmedText);
    // Before clearing 'textline', check if its length is 0 to avoid calling
    // this function infinitely many times.
    if (text.length() != 0) {
      textline->clear();
    }
  }
}

bool PrivKeyEnterReceiver::eventFilter(QObject *obj, QEvent *event) {
  if(event->type() == QEvent::KeyRelease) {
    QKeyEvent *key = static_cast<QKeyEvent *>(event);

    if((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
      dialog->privMsgEntered();
    } else {
      return QObject::eventFilter(obj, event);
    }
    return true;
  } else {
    return QObject::eventFilter(obj, event);
  }

  return false;
}

bool ChatKeyEnterReceiver::eventFilter(QObject *obj, QEvent *event) {
  if(event->type() == QEvent::KeyRelease) {
    QKeyEvent *key = static_cast<QKeyEvent *>(event);

    if((key->key() == Qt::Key_Enter) || (key->key() == Qt::Key_Return)) {
      dialog->myMessageEntered();
    } else {
      return QObject::eventFilter(obj, event);
    }
    return true;
  } else {
    return QObject::eventFilter(obj, event);
  }

  return false;
}

ChatDialog::ChatDialog(NetSocket* sock) {
  // 'Enter' detection for text entry box.
  key = new ChatKeyEnterReceiver();
  installEventFilter(key);
  key->dialog = this;
  fileMap = new FileMap();
  privMsgs = new QHash<QString, PrivDialog*>();
  this->sock = sock;
  messages = new MessageList();
  myOriginID = new QString("aefijaw");
  qsrand(QTime::currentTime().msec());
  myOriginID->append(QString::number(qrand()));

  setWindowTitle(QString::number(sock->myPort));

  // Read-only text box where we display messages from everyone.
  // This widget expands both horizontally and vertically.
  textview = new QTextEdit(this);
  textview->setReadOnly(true);

  // Text box where we enter messages.
  textline = new QTextEdit(this);
  textline->setFocus();

  QLabel *peerlineLabel = new QLabel("Host:addr of a peer:");
  peerline = new QLineEdit(this);
  connect(peerline, SIGNAL(returnPressed()), this, SLOT(hostAddrEntered()));

  QLabel *peerOriginsLabel = new QLabel("List of known origin ID's:");
  peerOrigins = new QListWidget(this);
  connect(peerOrigins, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this,
          SLOT(openPrivateMsgWindow(QListWidgetItem*)));

  QLabel *searchlineLabel = new QLabel("Search for a file.");
  searchline = new QLineEdit(this);
  connect(searchline, SIGNAL(returnPressed()), this,
      SLOT(searchQueryEntered()));

  QLabel *searchResultsLabel = new QLabel("Search results");
  searchResults = new QListWidget(this);
  connect(searchResults, SIGNAL(itemDoubleClicked(QListWidgetItem*)), this,
          SLOT(sendDownloadRequest(QListWidgetItem*)));

  m_button = new QPushButton("Share File(s)", this);
  connect(m_button, SIGNAL(released()), this, SLOT(handleButton()));
  m_button->setAutoDefault(false);

  // Lay out the widgets to appear in the main window.
  QVBoxLayout *layout = new QVBoxLayout();
  layout->addWidget(textview);
  layout->addWidget(textline);
  layout->addWidget(peerlineLabel);
  layout->addWidget(peerline);
  layout->addWidget(peerOriginsLabel);
  layout->addWidget(peerOrigins);
  layout->addWidget(m_button);
  layout->addWidget(searchlineLabel);
  layout->addWidget(searchline);
  layout->addWidget(searchResultsLabel);
  layout->addWidget(searchResults);
  setLayout(layout);
}

void ChatDialog::sendDownloadRequest(QListWidgetItem* item) {
  sock->sendDownloadRequest(item);
}

QByteArray ChatDialog::getMetafileHashes(QVariantList fileMatches) {
  QByteArray ret = QByteArray();
  for (int i = 0; i < fileMatches.size(); ++i) {
    QString fileName = fileMatches.at(i).toString();
    if (fileMap->count(fileName) == 0) {
      qDebug() << "File map did not contain file name, was expected to.";
    }
    ret.append(fileMap->at(fileName).hash);
  }
  return ret;
}

void ChatDialog::handleButton() {
  QFileDialog dialog(this);
  dialog.setFileMode(QFileDialog::AnyFile);
  QStringList fileNames = QFileDialog::getOpenFileNames(this);
  for (QString fileName : fileNames) {
    QFile f(fileName);
    f.open(QIODevice::ReadOnly);
    qint64 numBytes = f.bytesAvailable();

    FileData fd;
    fd.numBytes = numBytes;
    while (numBytes > 0) {
      fd.metafile.append(QCA::Hash("sha1").hash(f.read(8192)).toByteArray());
      numBytes -= 8192;
    }
    qDebug() << fd.metafile;

    fd.hash.append(QCA::Hash("sha1").hash(fd.metafile).toByteArray());
    fileMap->erase(fileName);
    fileMap->insert(make_pair(fileName, fd));
    f.close();
  }
}

void ChatDialog::openPrivateMsgWindow(QListWidgetItem *item) {
  // item->text() is an origin identifier.
  openPrivateMsgWindow(item->text());
}

void ChatDialog::openPrivateMsgWindow(QString text) {
  if (privMsgs->contains(text)) {
    privMsgs->value(text)->show();
  } else {
    PrivDialog* pd = new PrivDialog(this, text, sock);
    privMsgs->insert(text, pd);
    pd->show();
  }
}

void ChatDialog::hostAddrEntered() {
  sock->addPeer(peerline->text());
  peerline->clear();
}

void ChatDialog::searchQueryEntered() {
  sock->handleSearchRequest(searchline->text());
  searchline->clear();
}

void ChatDialog::myMessageEntered() {
  QString text = textline->toPlainText();
  if (text.length() > 0) {
    const QString trimmedText = text.trimmed().replace("\n", "");
    QVariantMap* map = sock->makeMyRumorMap(&trimmedText, new QString(), false);
    sock->incomingRQ.load()->push(map);
    sock->handleIncomingRQ();

    textview->append(trimmedText);
    // Before clearing 'textline', check if its length is 0 to avoid calling
    // this function infinitely many times.
    if (text.length() != 0) {
      textline->clear();
    }
  }
}

void ChatDialog::displayMsg(const QString& text, const QString& orig) {
  // Only display messages that are NOT from me. My messages are displayed
  // through another code path. This is to allow for smooth behavior when I am
  // not chatting with anyone else.
  if (orig.compare(*myOriginID) != 0) {
    textview->append(text.trimmed());
  }
}

QByteArray ChatDialog::findBlock(QByteArray blockHash) {
  for (FileMap::iterator it = fileMap->begin(); it != fileMap->end(); ++it) {
    FileData data = (FileData) it->second;
    QByteArray metafile = data.metafile;
    if (blockHash == data.hash) {
      return metafile;
    }

    if (metafile.length() % 20 != 0) {
      qDebug() << "metafile length not multiple of 20.";
    }
    int numBlocks = metafile.length() / 20;
    for (int i = 0; i < numBlocks; ++i) {
      if (match(metafile, blockHash, i)) {
        qDebug() << "Getting file block from it->first, which is: " << it->first;
        qDebug() << "returning: " << getFileBlock(it->first, i);
        return getFileBlock(it->first, i);
      }
    }
  }
  qDebug () << "findBlock: Couldn't find block hash. Returning empty qbytearray.";
  return QByteArray();
}

QByteArray ChatDialog::getFileBlock(const QString file, int i) {
  QFile f(file);
  f.open(QIODevice::ReadOnly);
  QByteArray ret = QByteArray();
  f.read(i * 8192);
  ret.append(f.read(8192));
  f.close();
  return ret;
}

bool ChatDialog::match(QByteArray metafile, QByteArray blockHash, int i) {
  int ix20 = i * 20;
  for (int j = 0; j < 20; ++j) {
    if (metafile.at(ix20 + j) != blockHash.at(j)) {
      return false;
    }
  }
  return true;
}

void ChatDialog::addMsg(QVariantMap* map) {
  QString orig = map->value(*(sock->originKey)).toString();
  QString text;
  if(map->contains(*(sock->chatTextKey))) {
    text = map->value(*(sock->chatTextKey)).toString();
  } else {
    text = QString::null;
  }
  if (messages.load()->count(orig) == 0) {
    vector<QString> emptyMessages;
    messages.load()->insert(make_pair(orig, emptyMessages));
  }
  messages.load()->at(orig).push_back(text);
}

NetSocket::NetSocket(QStringList args) {
  // Initialize constants
  incomingRQ = new queue< QVariantMap*>();
  outgoingRQ = new queue< QVariantMap*>();
  currentRumorMessage = NULL;
  blockReplyKey = new QString("BlockReply");
  blockRequestKey = new QString("BlockRequest");
  budgetKey = new QString("Budget");
  chatTextKey = new QString("ChatText");
  dataKey = new QString("Data");
  destKey = new QString("Dest");
  hopLimitKey = new QString("HopLimit");
  matchIDsKey = new QString("MatchIDs");
  matchNamesKey = new QString("MatchNames");
  originKey = new QString("Origin");
  searchReplyKey = new QString("SearchReply");
  searchRequestKey = new QString("Search");
  seqNoKey = new QString("SeqNo");
  wantKey = new QString("Want");
  lastIPKey = new QString("LastIP");
  lastPortKey = new QString("LastPort");
  routingTable = new QHash< QString, Destination*>();
  portWaitingFor = 0;
  forwarding = true;
  searching = false;
  IPwaitingFor = QHostAddress::Null;
  hostLookups = new HNLookupList();
  hashOfRequestedBlock = QByteArray();
  blocksRemaining = -1;
  nameOfRequestedFile = "";
  resultMap = new ResultMap();

  // Pick a range of four UDP ports to try to allocate by default, computed
  // based on my Unix user ID. This makes it trivial for up to four Peerster
  // instances per user to find each other on the same host, barring UDP port
  // conflicts with other applications (which are quite possible).
  // We use the range from 32768 to 49151 for this purpose.
  myPortMin = 32768 + (getuid() % 4096) * 4;
  myPortMax = myPortMin + 3;

  // Add in the peers given in the command line.
  for (int i = 1; i < args.size(); ++i) {
    QString s = args.at(i);
    if (s.at(0) == '-') {
      if (s == "-noforward") {
        qDebug() << "no forwarding detected.";
        forwarding = false;
      }
    } else {
      addPeer(args.at(i));
    }
  }

  // Anti Entropy
  QTimer *aeTimer = new QTimer(this);
  connect(aeTimer, SIGNAL(timeout()), this, SLOT(antiEntropy()));
  aeTimer->start(10000);

  // Route rumor
  QTimer *rrTimer = new QTimer(this);
  connect(rrTimer, SIGNAL(timeout()), this, SLOT(routeRumor()));
  rrTimer->start(60000);

  // Register a callback for whenever datagrams are received, so that their
  // message (if they are of the correct form) can be displayed in the text
  // window.
  connect(this, SIGNAL(readyRead()), this, SLOT(readMessage()));
}

void NetSocket::sendDownloadRequest(QListWidgetItem* item) {
  QString fileName = item->text();
  ResultData resultData = resultMap->at(fileName);
  const QString dest = resultData.uploaderDest;
  QByteArray hash = resultData.hash;
  qDebug() << "Hash of file is: " << hash;
  requestingMetafile = true;
  requestingDataBlock = false;
  nameOfRequestedFile = fileName;
  sendBlockRequest(&dest, *(dialog->myOriginID), (quint32) 10, hash);
}

void NetSocket::routeRumor() {
  quint32 seqno;
  MessageList* myMessages = dialog->messages.load();
  if (myMessages->count(*(dialog->myOriginID)) == 0) {
    seqno = 1;
  } else {
    seqno = (quint32) myMessages->at(*(dialog->myOriginID)).size() + 1;
  }

  QVariantMap* map = new QVariantMap();
  map->insert(*originKey, *(dialog->myOriginID));
  map->insert(*seqNoKey, seqno);
  incomingRQ.load()->push(map);
  handleIncomingRQ();
}

void NetSocket::addPeer(QString arg) {
  int i = arg.indexOf(':');
  if (i <= 0 || i == arg.size() - 1) {
    qDebug() << "Specified peer needs form host:port";
    return;
  }

  QStringList list = arg.split(':');
  QString host = list.at(0);
  QString portStr = list.at(1);
  if (portStr.indexOf(':') != -1) {
    qDebug() << "Two colons detected in specified peer.  Needs form host:port.";
    return;
  }

  quint16 port = portStr.toUShort();
  
  QHostAddress address;
  // Try to parse 'host' as an IP address. If this doesn't work, then treat
  // 'host' as a hostname and look up its corresponding IP.
  if (!address.setAddress(host)) {
    hostLookups.load()->insert(make_pair(host, port));
    QHostInfo::lookupHost(host, this, SLOT(lookedUpHost(QHostInfo)));
  }
}

void NetSocket::lookedUpHost(const QHostInfo &host) {
  if (hostLookups.load()->count(host.hostName()) == 0) {
    qDebug() << "lookedUpHost: Host name has already been looked up.";
    return;
  }

  if (host.error() != QHostInfo::NoError) {
    qDebug() << "Lookup failed:" << host.errorString();
    return;
  }

  qDebug() << "Lookup succeeded.";

  QHostAddress addr = host.addresses().first();
  findOrAddPeer(addr, hostLookups.load()->at(host.hostName()));
  hostLookups.load()->erase(host.hostName());
}

void NetSocket::antiEntropy() {
  Peer* peer = getRandomPeer();
  sendStatusMessage(peer);
}

bool NetSocket::bind() {
  // Try to bind to each of the range myPortMin..myPortMax in turn.
  for (quint16 p = myPortMin; p <= myPortMax; p++) {
    if (QUdpSocket::bind(p)) {
      myPort = p;
	    qDebug() << "bound to UDP port " << p;

      // Add in the default peers as soon as I know my port.
      for (quint16 i = 1; i < 4; ++i) {
        quint16 port = myPort + i;
        if (port > myPortMax) {
          port -= 4;
        }
        findOrAddPeer(QHostAddress::LocalHost, port);
      }

      return true;
    }
  }

  qDebug() << "Oops, no ports in my default range " << myPortMin
    << "-" << myPortMax << " available";
  return false;
}

Peer* NetSocket::findOrAddPeer(QHostAddress address, quint16 port) {
  for (Peer* peer : peers) {
    if (peer->IP == address && peer->port == port) {
      return peer;
    }
  }
  
  // Peer not found. Create new peer.
  Peer* peer = new Peer();
  peer->IP = address;
  peer->port = port;
  peers.push_back(peer);
  return peer;
}

Peer* NetSocket::getRandomPeer() {
  return peers.at(rand() % peers.size());
}

QVariantMap* NetSocket::makeMyRumorMap(const QString* text, const QString* dest,
     bool priv) {
  QVariantMap* map = new QVariantMap();
  map->insert(*chatTextKey, *text);
  map->insert(*originKey, *(dialog->myOriginID));
  if (priv) {
    map->insert(*hopLimitKey, (quint32) 10);
    map->insert(*destKey, *dest);
  } else {
    MessageList* myMessages = dialog->messages.load();
    quint32 seqno;
    if (myMessages->count(*(dialog->myOriginID)) == 0) {
      seqno = 1;
    } else {
      seqno = (quint32) myMessages->at(*(dialog->myOriginID)).size() + 1;
    }
    map->insert(*seqNoKey, seqno);
  }
  return map;
}

void NetSocket::sendMap(QVariantMap* map, Destination* dest) {
  Peer peer;
  peer.IP = dest->IP;
  peer.port = dest->port;
  sendMap(map, &peer);
}

void NetSocket::sendMap(QVariantMap *map, Peer* peer) {
  QByteArray a;
  QDataStream s(&a, QIODevice::WriteOnly);
  s << *map;

  writeDatagram(a, peer->IP, peer->port);
}

void NetSocket::sendRumor(Peer* peer, QString text, QString orig,
      quint32 seqno) {
  QVariantMap *map = new QVariantMap();
  // Route rumor messages were stored as QString::null in the message vector.
  if (!text.isNull()) {
    map->insert(*chatTextKey, text);
  }
  map->insert(*originKey, orig);
  map->insert(*seqNoKey, seqno);
  sendMap(map, peer);
}

void NetSocket::handleSearchRequest(QString text) {
  searching = true;
  searchText = text;
  dialog->searchResults->clear();
  searchBudget = (quint32) 2;
  numMatches = 0;
  resultMap = new ResultMap();
  srTimer = new QTimer(this);
  connect(srTimer, SIGNAL(timeout()), this, SLOT(sendSearch()));
  srTimer->start(1000);
}

void NetSocket::sendSearch() {
  for (Peer* peer : peers) {
    QVariantMap* map = new QVariantMap();
    map->insert(*originKey, *(dialog->myOriginID));
    map->insert(*searchRequestKey, searchText);
    if (searchBudget != (quint32) 128 && numMatches <= 10) {
      searchBudget *= 2;
      map->insert(*budgetKey, searchBudget);
      sendMap(map, peer);
    } else {
      srTimer->stop();
    }
  }
}

void NetSocket::sendSearchReply(QVariantMap* map, QVariantList fileMatches) {
  QVariantMap* repMap = new QVariantMap();
  repMap->insert(*destKey, map->value(*originKey).toString());
  repMap->insert(*originKey, *(dialog->myOriginID));
  repMap->insert(*hopLimitKey, (quint32) 10);
  repMap->insert(*searchReplyKey, map->value(*searchRequestKey).toString());
  repMap->insert(*matchIDsKey, dialog->getMetafileHashes(fileMatches));

  // After the metafile hashes have been obtained note that 'fileMatches' is
  // still filled with things like '/c/cs426/home/notes.txt'.  We should replace
  // all those entries with simply the filenames, like 'notes.txt'.
  repMap->insert(*matchNamesKey, stripPaths(fileMatches));
  qDebug() << "Sending search reply: " << *repMap;
  sendMap(repMap, routingTable->value(repMap->value(*destKey).toString()));
}

QList<QVariant> NetSocket::stripPaths(QList<QVariant> list) {
  QList<QVariant> newList;
  for (QVariant v : list) {
    newList.append(v.toString().split('/').last());
  }
  return newList;
}

void NetSocket::sendBlockRequest(const QString* dest, QString orig,
                                 quint32 hopLimit, QByteArray blockRequest) {
  requestMap = new QVariantMap();
  hashOfRequestedBlock = blockRequest;
  requestMap->insert(*destKey, *dest);
  requestMap->insert(*originKey, orig);
  requestMap->insert(*hopLimitKey, hopLimit);
  requestMap->insert(*blockRequestKey, blockRequest);
  if (routingTable->contains(*dest)) {
    requestDest = routingTable->value(*dest);
    requestingBlock = true;
    sendMap(requestMap, requestDest);

    brTimer = new QTimer(this);
    connect(brTimer, SIGNAL(timeout()), this, SLOT(sendMapBlockRequest()));
    brTimer->start(3000);
  } else {
    qDebug() << "Error. routing table did not contain: " << *dest;
  }
}

void NetSocket::sendMapBlockRequest() {
  if (requestingBlock) {
    sendMap(requestMap, requestDest);
  } else {
    brTimer->stop();
  }
}

void NetSocket::sendBlockReply(QVariantMap* map) {
  quint32 hopLimit = 10;
  map->insert(*hopLimitKey, hopLimit);
  QByteArray blockHash = map->value(*blockRequestKey).toByteArray();

  // Swap dest and origin.
  // Beware of trying to access old dest / origin values in the future.
  map->insert(*destKey, map->value(*originKey).toString());
  map->insert(*originKey, *(dialog->myOriginID));

  map->remove(*blockRequestKey);
  QByteArray data = dialog->findBlock(blockHash);
  QByteArray dataHash = QByteArray();
  dataHash.append(QCA::Hash("sha1").hash(data).toByteArray());

  map->insert(*dataKey, data);
  map->insert(*blockReplyKey, dataHash);

  const QString dest = map->value(*destKey).toString();
  if (routingTable->contains(dest)) {
    qDebug() << "Sending block reply: " << *map;
    sendMap(map, routingTable->value(dest));
  }
}

void NetSocket::sendStatusMessage(Peer* peer) {
  // Construct and send the status message.
  QVariantMap* map = new QVariantMap();
  QVariantMap* wantMap = new QVariantMap();
  MessageList* myMessages = dialog->messages.load();
  for (MessageList::iterator it = myMessages->begin();
      it != myMessages->end(); ++it) {
    wantMap->insert(it->first, (quint32) it->second.size() + 1);
  }
  map->insert(*wantKey, *wantMap);
  sendMap(map, peer);
}

bool NetSocket::isRouteRumor(QVariantMap* map) {
  return (!map->contains(*chatTextKey) && map->contains(*originKey)
      && map->contains(*seqNoKey));
}

bool NetSocket::isRumorWithText(QVariantMap* map) {
  return (map->contains(*chatTextKey) && map->contains(*originKey)
      && map->contains(*seqNoKey));
}

bool NetSocket::isPrivRumor(QVariantMap* map) {
  return (map->size() == 4 && map->contains(*chatTextKey)
      && map->contains(*originKey) && map->contains(*destKey)
      && map->contains(*hopLimitKey));
}

bool NetSocket::isBlockReply(QVariantMap* map) {
  return (map->size() == 5 && map->contains(*destKey)
      && map->contains(*originKey) && map->contains(*hopLimitKey)
      && map->contains(*blockReplyKey) && map->contains(*dataKey));
}

bool NetSocket::isBlockRequest(QVariantMap* map) {
  return (map->size() == 4 && map->contains(*destKey)
      && map->contains(*originKey) && map->contains(*hopLimitKey)
      && map->contains(*blockRequestKey));
}

bool NetSocket::isSearchRequest(QVariantMap* map) {
  return (map->size() == 3 && map->contains(*originKey)
      && map->contains(*searchRequestKey) && map->contains(*budgetKey));
}

bool NetSocket::isSearchReply(QVariantMap* map) {
  return map->size() == 6 && map->contains(*destKey)
      && map->contains(*originKey) && map->contains(*hopLimitKey)
      && map->contains(*searchReplyKey) && map->contains(*matchNamesKey)
      && map->contains(*matchIDsKey);
}

bool NetSocket::isStatusMessage(QVariantMap* map) {
  return (map->size() == 1 && map->contains(*wantKey));
}

void NetSocket::handleStatusMessage(QVariantMap* map, Peer* peer, 
    quint16 port) {
  if (portWaitingFor == port && IPwaitingFor == peer->IP) {
    portWaitingFor = 0;
    IPwaitingFor = QHostAddress::Null;
  }

  // A status was received.  We're not currently waiting on any rumor.
  QVariantMap* oldRumorMessage = currentRumorMessage.load();
  currentRumorMessage = NULL;

  // Experimental line: Whenever CRM is set to NULL, try handling the outgoing
  // RQ again.
  handleOutgoingRQ();

  const QVariantMap wantMap = map->value(*wantKey).toMap();

  MessageList* myMessages = dialog->messages.load();
  bool theyNeed = false;
  bool iNeed = false;

  // Give them all the mesages they don't have, out of our shared origin IDs.
  for (QVariantMap::const_iterator it = wantMap.begin();
      it != wantMap.end(); ++it) {
    quint32 theirWant = it.value().toUInt();
    quint32 myWant;
    if (myMessages->count(it.key()) == 0) {
      myWant = 1;
    } else {
      myWant = myMessages->at(it.key()).size() + 1;
    }

    if (!iNeed && (myMessages->count(it.key()) == 0 || theirWant > myWant)) {
      iNeed = true;
      sendStatusMessage(peer);
    }
    if (myWant > theirWant && forwarding) {
      theyNeed = true;
      vector<QString> messages = myMessages->at(it.key());
      for (quint32 n = theirWant; n < myWant; ++n) {
        sendRumor(peer, messages.at(n - 1), it.key(), n);
      }
    }
  }

  // Iterate through all my messages. If I have origin IDs that they don't have,
  // send all those messages from those origin IDs to them.
  for (MessageList::iterator it = myMessages->begin();
      it != myMessages->end(); ++it) {
    vector<QString> messages = myMessages->at(it->first);
    if (!wantMap.contains(it->first)) {
      for (quint32 n = 0; n < messages.size(); ++n) {
        sendRumor(peer, messages.at(n), it->first, n + 1);
      }
    }
  }

  if (!iNeed && !theyNeed && rand() % 2 == 0 && oldRumorMessage != NULL) {
    incomingRQ.load()->push(oldRumorMessage);
    handleIncomingRQ();
  }
}

void NetSocket::readMessage() {
  if (hasPendingDatagrams()) {
    QByteArray buf(pendingDatagramSize(), Qt::Uninitialized);
    QDataStream str(&buf, QIODevice::ReadOnly);
    QVariantMap *map = new QVariantMap();
    QHostAddress address;
    quint16 port;
    readDatagram(buf.data(), buf.size(), &address, &port);
    str >> *map;

    Peer* peer = findOrAddPeer(address, port);
    QString orig = map->value(*originKey).toString();

    if (isPrivRumor(map) || isBlockRequest(map) || isBlockReply(map) ||
        isSearchReply(map)) {
      handleForwardable(map, orig);
    } else if (isSearchRequest(map)
              && map->value(*originKey).toString() != *(dialog->myOriginID)) {
      handleIncomingSearchRequest(map);
    } else if (isRumorWithText(map) || isRouteRumor(map)) {
      handleIncomingRumorMsg(map, orig, address, port, peer);
    } else if (isStatusMessage(map)) {
      handleStatusMessage(map, peer, port);
    }
  }
}

// By this point I already know it's for me.
void NetSocket::handleSearchReply(QVariantMap* map) {
  if (map->value(*searchReplyKey).toString() == searchText) {
    QVariantList matchNames = map->value(*matchNamesKey).toList();
    for (int i = 0; i < matchNames.size(); ++i) {
      QString fileName = matchNames.at(i).toString();
      if (resultMap->count(fileName) == 0) {
        numMatches++;
        ResultData data;
        data.hash = getByteArraySubset(i,
            map->value(*matchIDsKey).toByteArray());
        data.uploaderDest = map->value(*originKey).toString();
        resultMap->insert(make_pair(fileName, data));
        new QListWidgetItem(fileName, dialog->searchResults);
      }
    }
  }
}

QByteArray NetSocket::getByteArraySubset(int i, QByteArray b) {
  QByteArray c;
  int ix20 = 20 * i;
  for (int j = 0; j < 20; ++j) {
    c.append(b.at(ix20 + j));
  }
  return c;
}

void NetSocket::handleIncomingSearchRequest(QVariantMap* map) {
  QVariantList fileMatches =
      findQueryMatches(map->value(*searchRequestKey).toString());
  if (!fileMatches.empty()) {
    sendSearchReply(map, fileMatches);
  }
  if (map->value(*budgetKey).toUInt() > 0) {
    distributeSearchQuery(map);
  }
}

void NetSocket::handleForwardable(QVariantMap* map, QString orig) {
  QString destOrigin = map->value(*destKey).toString();
  if (destOrigin.compare(*(dialog->myOriginID)) != 0) {
    // Private message / block request not for me.
    if (forwarding) {
      quint32 hopsLeft = map->value(*hopLimitKey).toUInt() - 1;
      if (hopsLeft > 0) {
        map->insert(*hopLimitKey, hopsLeft);
        if (routingTable->contains(destOrigin)) {
          sendMap(map, routingTable->value(destOrigin));
        }
      }
    }
  } else if (isPrivRumor(map)) {
      dialog->openPrivateMsgWindow(orig);
      QString text = map->value(*chatTextKey).toString();
      dialog->privMsgs->value(orig)->textview->append(text);
  } else if (isBlockRequest(map)) {
    qDebug() << "Received block request, sending block reply.";
    sendBlockReply(map);
  } else if (isBlockReply(map)) {
    qDebug() << "Received block reply.";
    handleBlockReply(map);
  } else if (isSearchReply(map)) {
    qDebug() << "Received search reply: " << *map;
    handleSearchReply(map);
  }
  return;
}

// Will be overwriting budget field. Don't try to access old budget field
// value in the future!
void NetSocket::distributeSearchQuery(QVariantMap* map) {
  quint32 budget = map->value(*budgetKey).toUInt();
  quint32 numNeighbors = peers.size();
  if (numNeighbors > budget) {
    QList<Peer*> sendTo;
    for (quint32 i = (quint32) 0; i < budget; ++i) {
      Peer* poss = getRandomPeer();
      if (!sendTo.contains(poss)) {
        sendTo.append(poss);
      }
    }
    map->insert(*budgetKey, (quint32) 1);
    for (Peer* peer : sendTo) {
      sendMap(map, peer);
    }
  } else {
    int numExtra = budget % numNeighbors;
    int numNormal = budget - numExtra;
    QList<Peer*> classAPeer;
    QList<Peer*> classBPeer;
    for (int i = 0; i < numExtra; ++i) {
      Peer* poss = getRandomPeer();
      if (!classAPeer.contains(poss)) {
        classAPeer.append(poss);
      }
    }
    for (int i = 0; i < numNormal; ++i) {
      Peer* poss = getRandomPeer();
      if (!classAPeer.contains(poss) && !classBPeer.contains(poss)) {
        classBPeer.append(poss);
      }  
    }

    map->insert(*budgetKey, (quint32) (budget / numNeighbors + 1));
    for (Peer* peer : classAPeer) {
      sendMap(map, peer);
    }
    map->insert(*budgetKey, (quint32) (budget / numNeighbors));
    for (Peer* peer : classBPeer) {
      sendMap(map, peer);
    }
  }
}

void NetSocket::handleIncomingRumorMsg(QVariantMap* map, QString orig,
    QHostAddress address, quint16 port, Peer* peer) {
  quint32 seqno = map->value(*seqNoKey).toUInt();

  // Add/update the lastIP / lastPort node in my peers list.
  // Casting is required for lastIP, because it was stored as a quint32.
  if (map->contains(*lastIPKey) && map->contains(*lastPortKey)) {
    QHostAddress* lastIP = new QHostAddress(map->value(*lastIPKey).toUInt());
    quint16 lastPort = map->value(*lastPortKey).toInt();
    if (*lastIP != QHostAddress::LocalHost || lastPort != myPort) {
      findOrAddPeer(*lastIP, lastPort);
    }
  }

  // Add/update this node in my routing table.
  if (orig.compare(*(dialog->myOriginID)) != 0) {
    if (!routingTable->contains(orig)) {
      new QListWidgetItem(orig, dialog->peerOrigins);
      Destination* dest = new Destination();
      updateDest(dest, address, port, seqno);
      routingTable->insert(orig, dest);
    } else {
      // I do have an entry for this Origin; update the entry if the
      // sequence number is higher, or if the sequence no's are the same AND
      // the route is direct.
      Destination* dest = routingTable->value(orig);
      if ((seqno > dest->seqno)
          || (seqno == dest->seqno && !map->contains(*lastPortKey)
              && !map->contains(*lastIPKey))) {
        updateDest(dest, address, port, seqno);
      }
    }
  }

  map->insert(*lastIPKey, address.toIPv4Address());
  map->insert(*lastPortKey, port);

  if (isNewRumor(map)) {
    incomingRQ.load()->push(map);
    handleIncomingRQ();
  }

  sendStatusMessage(peer);
}

void NetSocket::handleBlockReply(QVariantMap* map) {
  // Check if hash of "Data" value matches the "BlockReply" value.
  QByteArray data = map->value(*dataKey).toByteArray();
  QByteArray blockReply = map->value(*blockReplyKey).toByteArray();
  QString dataHash = QCA::Hash("sha1").hash(data).toByteArray();
  // New dest is old origin.
  QString destOrigin = map->value(*originKey).toString();

  if (hashOfRequestedBlock == dataHash
      && dataHash == blockReply) {
    requestingBlock = false;
    if (requestingMetafile && !requestingDataBlock) {
      qDebug() << "Got my metafile:" << *map;
      requestingMetafile = false;
      requestingDataBlock = true;
      blocksRemaining = data.size() / 20;
      if (data.size() % 20 != 0) {
        qDebug() << "Got metafile with # of Chars not divisible by 20.";
      }
      QByteArray firstBlock = data.left(20);
      metafileOfRequestedBlock = data;
      metafileOfRequestedBlock.remove(0, 20);
      sendBlockRequest(&destOrigin, *(dialog->myOriginID), (quint32) 10,
                       firstBlock);
      fileAccumulating = QByteArray();
    } else if (!requestingMetafile && requestingDataBlock) {
      qDebug() << "Got my block:" << *map;
      fileAccumulating.append(data);
      blocksRemaining--;
      if (blocksRemaining > 0) {
        if (data.size() != 8192) {
          qDebug() << "Received nonfinal file block of size != 8192";
        }
        sendBlockRequest(&destOrigin, *(dialog->myOriginID),
                         (quint32) 10,
                         metafileOfRequestedBlock.left(20));
        metafileOfRequestedBlock.remove(0, 20);
      } else if (blocksRemaining == 0) {
        qDebug() << "No blocks remaining. Writing to file!";
        requestingDataBlock = false;
        QFile file(nameOfRequestedFile);
        file.open(QIODevice::WriteOnly);
        file.write(fileAccumulating);
        file.close();
      }
    } else {
      qDebug() << "Not requesting metafile or data block (or requesting both).";
    }
  }
}

QVariantList NetSocket::findQueryMatches(QString query) {
  FileMap* fileMap = dialog->fileMap;
  QVariantList response = QVariantList();
  for (FileMap::iterator it = fileMap->begin(); it != fileMap->end(); ++it) {
    if (it->first.split('/').last() == query) {
      response.append(it->first);
    }
  }
  return response;
}

void NetSocket::updateDest(Destination* dest, QHostAddress addr, quint16 port,
    quint32 seqno) {
  dest->IP = addr;
  dest->port = port;
  dest->seqno = seqno;
}

bool NetSocket::isNewRumor(QVariantMap* map) {
  QString orig = map->value(*originKey).toString();
  quint32 seqno = map->value(*seqNoKey).toUInt();
  MessageList* myMessages = dialog->messages.load();
  if (myMessages->count(orig) == 0) {
    return true;
  }
  return seqno > myMessages->at(orig).size();
}

bool NetSocket::isNextRumor(QVariantMap* map) {
  QString orig = map->value(*originKey).toString();
  quint32 seqno = map->value(*seqNoKey).toUInt();
  MessageList* myMessages = dialog->messages.load();
  if (myMessages->count(orig) == 0) {
    return seqno == 1;
  }
  quint32 myNum = myMessages->at(orig).size();
  return (seqno == myNum + 1);
}

void NetSocket::handleIncomingRQ() {
  while (incomingRQ.load()->size() != 0) {
    QVariantMap* map = incomingRQ.load()->front();
    incomingRQ.load()->pop();

    // Only add it if it's the next one I need, and rumormonger it. If it's
    // not the next one I need, it IS safe to discard, because a status
    // message was sent when this rumor was received. So I should be (later)
    // getting the missing messages from at least the node that sent me this
    // rumor.
    if (isNextRumor(map)) {
      if (isRumorWithText(map)) {
        dialog->displayMsg(map->value(*chatTextKey).toString(),
                           map->value(*originKey).toString());
      }
      dialog->addMsg(map);
      outgoingRQ.load()->push(map);
      handleOutgoingRQ();
    }
  }
}

void NetSocket::handleOutgoingRQ() {
  while (outgoingRQ.load()->size() != 0 && currentRumorMessage == NULL) {
    QVariantMap* map = outgoingRQ.load()->front();
    outgoingRQ.load()->pop();

    if (map->value(*originKey) == *(dialog->myOriginID)
        || forwarding || !map->contains(*chatTextKey)) {
      currentRumorMessage = map;
      rumor(map);
    }
  }
}

void NetSocket::rumor(QVariantMap* map) {
  if (!map->contains(*chatTextKey)) {
    // If it's a rumor route message, send it to all peers.
    for (Peer* peer : peers) {
      sendMap(map, peer);
    }
  } else {
    Peer* peer = getRandomPeer();
    sendMap(map, peer);

    portWaitingFor = peer->port;
    IPwaitingFor = peer->IP;

    QTimer *timer = new QTimer(this);
    timer->setSingleShot(true);
    connect(timer, SIGNAL(timeout()), this, SLOT(rumorTimeout()));
    timer->start(1000);
  }
}

void NetSocket::rumorTimeout() {
  if (portWaitingFor != 0) {
    // Timed out waiting for a status message.
    portWaitingFor = 0;
    IPwaitingFor = QHostAddress::Null;
    QVariantMap* map = currentRumorMessage;

    if (map != NULL) {
      rumor(map);
    }
  }
}

int main(int argc, char **argv) {
  testFunc();

  // Initialize Qt toolkit
  QApplication app(argc,argv);

  QCA::Initializer qcainit;

  // Create a UDP network socket
  NetSocket* sock = new NetSocket(QCoreApplication::arguments());
  if (!sock->bind())
    exit(1);

  // Create an initial chat dialog window
  ChatDialog dialog(sock);
  sock->dialog = &dialog;
  dialog.show();
  sock->routeRumor();

  // Enter the Qt main loop; everything else is event driven
  return app.exec();
}

