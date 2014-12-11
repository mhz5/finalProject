#ifndef PEERSTER_MAIN_HH
#define PEERSTER_MAIN_HH

#include <atomic>
#include <queue>
#include <map>

#include <QByteArray>
#include <QDialog>
#include <QHash>
#include <QHostInfo>
#include <QLineEdit>
#include <QListWidget>
#include <QPair>
#include <QtGui/QPushButton>
#include <QTextEdit>
#include <QUdpSocket>
#include <QVariantMap>

using namespace std;

class ChatDialog;
class ChatKeyEnterReceiver;
class Destination;
class FileData;
class NetSocket;
class Peer;
class PrivDialog;
class PrivKeyEnterReceiver;
class ResultData;
class SelectFileDialog;

typedef map< const QString, FileData> FileMap;
typedef map< const QString, vector<QString> > MessageList;
typedef map< const QString, quint16> HNLookupList;
typedef map< const QString, ResultData> ResultMap;

// For any peers A and B, there is a FileVote indicating the results of all votes
// by peer A on peer B's files.
typedef QMap< QString, int> FileVote;

// For any peer, this maps the file uploader to a list of files voted by the peer,
// and + or -1 for each file.
typedef QMap< QString, FileVote> UploaderFileVote;

// Maps peer to an UploaderFileVote.  Covers everything.
typedef QMap< QString, UploaderFileVote> VotingHistory;

// Value in the hash tree.
class FileData {
public:
  quint64 numBytes;
  QByteArray metafile;
  QByteArray hash;
};

class ResultData {
public:
  QByteArray hash;
  QString uploaderDest;
};

class PrivDialog : public QDialog {
  Q_OBJECT

public:
  PrivDialog(ChatDialog* dialog, QString origin, NetSocket* sock);
  void privMsgEntered();

  ChatDialog* cDialog;
  PrivKeyEnterReceiver* key;
  QString origin;
  NetSocket *sock;
  QTextEdit *textline;
  QTextEdit *textview;
};

class VoteDialog : public QDialog {
  Q_OBJECT

public:
  VoteDialog();

public slots:
  void upvoted();
  void downvoted();
};

class ChatDialog : public QDialog {
  Q_OBJECT

public:
  ChatDialog(NetSocket* sock);
  void addMsg(QVariantMap* map);
  void displayMsg(const QString& text, const QString& orig);
  QByteArray findBlock(QByteArray blockHash);
  QByteArray getFileBlock(const QString file, int i);
  QByteArray getMetafileHashes(QVariantList fileMatches);
  bool match(QByteArray metafile, QByteArray blockHash, int i);
  void myMessageEntered();
  void openPrivateMsgWindow(QString origin);

  atomic< MessageList*> messages;
  QString* myOriginID;
  ChatKeyEnterReceiver* key;
  QListWidget *peerOrigins;
  QListWidget *searchResults;
  FileMap* fileMap;
  NetSocket *sock;
  QHash <QString, PrivDialog*>* privMsgs;
  QLineEdit *peerline;
  QLineEdit *searchline;
  QPushButton *m_button;
  QTextEdit *textline;
  QTextEdit *textview;

public slots:
  void handleButton();
  void hostAddrEntered();
  void openPrivateMsgWindow(QListWidgetItem *item);
  void searchQueryEntered();
  void sendDownloadRequest(QListWidgetItem* item);
};

class NetSocket : public QUdpSocket {
  Q_OBJECT

public:
  NetSocket(QStringList);

  void addPeer(QString);
  void addVote(QString voter, QString uploader, QString filename, int res);
  bool bind();
  double calculateScore(QString uploader, QString filename);
  QStringList* convertToStringList(VotingHistory* vh) ;
  void distributeSearchQuery(QVariantMap* map);
  Peer* findOrAddPeer(QHostAddress address, quint16 port);
  QVariantList findQueryMatches(QString query);
  Peer* getRandomPeer();
  QByteArray getByteArraySubset(int i, QByteArray b);
  void handleBlockReply(QVariantMap* map);
  void handleForwardable(QVariantMap* map, QString orig);
  void handleIncomingRQ();
  void handleIncomingRumorMsg(QVariantMap* map, QString orig,
      QHostAddress address, quint16 port, Peer* peer);
  void handleIncomingSearchRequest(QVariantMap* map);
  void handleOutgoingRQ();
  void handleSearchReply(QVariantMap* map);
  void handleSearchRequest(QString text);
  void handleStatusMessage(QVariantMap* map, Peer* peer, quint16 port);
  void handleVoteHistory(QVariantMap* map, Peer* peer);
  bool isBlockReply(QVariantMap* map);
  bool isBlockRequest(QVariantMap* map);
  bool isNewRumor(QVariantMap* map);
  bool isNextRumor(QVariantMap* map);
  bool isPrivRumor(QVariantMap* map);
  bool isRouteRumor(QVariantMap* map);
  bool isRumorWithText(QVariantMap* map);
  bool isSearchReply(QVariantMap* map);
  bool isSearchRequest(QVariantMap* map);
  bool isStatusMessage(QVariantMap* map);
  bool isVoteHistory(QVariantMap* map);
  QVariantMap* makeMyRumorMap(const QString* text, const QString* orig,
                              bool priv);
  void openVoteDialog();
  void rumor(QVariantMap* map);
  void sendBlockReply(QVariantMap* map);
  void sendBlockRequest(const QString* dest, QString orig, quint32 hopLimit,
                        QByteArray blockRequest);
  void sendDownloadRequest(QListWidgetItem* item);
  void sendMap(QVariantMap* map, Destination* dest);
  void sendMap(QVariantMap* map, Peer* peer);
  void sendRumor(Peer* peer, QString text, QString orig,
      quint32 seqno);
  void sendVH(Peer* peer, int tag);
  void sendSearchReply(QVariantMap* map, QVariantList fileMatches);
  void sendStatusMessage(Peer* peer);
  double similarity(QString voter);
  QList<QVariant> stripPaths(QList<QVariant> list);
  void updateDest(Destination*, QHostAddress addr, quint16 port, quint32 seqno);
  void updateVH(QStringList* vh);
  int voted(QString voter, QString uploader, QString filename);
  bool wantRumorMessage(QVariantMap* map);

  atomic< queue< QVariantMap*>*> incomingRQ;
  atomic< queue< QVariantMap*>*> outgoingRQ;
  atomic< HNLookupList*> hostLookups;
  bool searching;
  ChatDialog *dialog;
  bool forwarding;
  bool requestingDataBlock;
  bool requestingMetafile;
  int blocksRemaining;
  int numMatches;
  ResultMap* resultMap;
  QByteArray fileAccumulating;
  QByteArray metafileOfRequestedBlock;
  QString curUploader;
  QString hashOfRequestedBlock;
  QString nameOfRequestedFile;
  QString searchText;
  QHash< QString, Destination*>* routingTable;
  QTimer *srTimer;
  quint16 myPortMin, myPortMax, myPort;
  quint32 searchBudget;
  vector<Peer*> peers;
  VoteDialog* curvd;
  QVariantMap* requestMap;
  Destination* requestDest;
  bool requestingBlock;
  QTimer* brTimer;
  VotingHistory* votingHistory;

  const QString* blockRequestKey;
  const QString* blockReplyKey;
  const QString* budgetKey;
  const QString* chatTextKey;
  const QString* dataKey;
  const QString* destKey;
  const QString* hopLimitKey;
  const QString* lastIPKey;
  const QString* lastPortKey;
  const QString* matchIDsKey;
  const QString* matchNamesKey;
  const QString* originKey;
  const QString* searchReplyKey;
  const QString* searchRequestKey;
  const QString* seqNoKey;
  const QString* tagKey;
  const QString* vhKey;
  const QString* wantKey;

public slots:
  void antiEntropy();
  void lookedUpHost(const QHostInfo &host);
  void readMessage();
  void routeRumor();
  void rumorTimeout();
  void sendMapBlockRequest();
  void sendSearch();
  void tabulateVote();

private:
  atomic<quint16> portWaitingFor;
  QHostAddress IPwaitingFor;
  atomic<QVariantMap*> currentRumorMessage;
};

class ChatKeyEnterReceiver: public QObject {
  Q_OBJECT

public:
  ChatDialog* dialog;
  bool eventFilter(QObject *obj, QEvent *event);
};

class PrivKeyEnterReceiver: public QObject {
  Q_OBJECT

public:
  PrivDialog* dialog;
  bool eventFilter(QObject *obj, QEvent *event);
};

class Destination {
  public:
    QHostAddress IP;
    quint16 port;
    quint32 seqno;
};

class Peer {
  public:
    QString hostName;
    QHostAddress IP;
    quint16 port;
};

#endif // PEERSTER_MAIN_HH
