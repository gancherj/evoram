// Written by Peter

#ifndef COMMON_NETWORKMANAGER
#define COMMON_NETWORKMANAGER

#include "BinaryStream.hpp"

#include "boost/asio.hpp"
#include "boost/lexical_cast.hpp"

#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#ifdef SendMessage
#undef SendMessage
#endif


#ifdef NDEBUG

#define SET_THREAD_NAME(_Expression)     ((void)0)

#else  /* NDEBUG */

#define   SET_THREAD_NAME(_Expression) SetThreadName(_Expression);
#endif
#ifdef MSVS
   void SetThreadName(const char* threadName, DWORD dwThreadID = -1);
#else
   void SetThreadName(const char* threadName, int dwThreadID = -1);
#endif

struct SendBuffer
{
  const void* data;
  uint32_t size;
  std::unique_ptr<std::vector<char>> optVectPtr;
  std::unique_ptr<BinaryStream> optBinStrPtr;
  std::mutex* mtx;
  std::condition_variable* cond;

  SendBuffer()
     :mtx(nullptr),
     cond(nullptr)
  {}

  ~SendBuffer()
  {


     try
     {
        optVectPtr.reset(nullptr);
        optBinStrPtr.reset(nullptr);
     }
     catch (std::exception& ex)
     {
        std::cout << ex.what() << std::endl;

     }
  }
};

class Channel :public std::enable_shared_from_this<Channel>
{
public:
  Channel(boost::asio::io_service& io_service,
     size_t channelIdx,
     std::unique_ptr<boost::asio::ip::tcp::socket> socket);

  ~Channel();

  void Stop();

  void AsyncSendMessageCopy(const void * bufferPtr, size_t length);
  void AsyncSendMessage(const void * bufferPtr, size_t length);
  void AsyncSendMessage(std::unique_ptr<std::vector<char>> buffer);
  void AsyncSendMessage(std::unique_ptr<BinaryStream> buffer);
  void SendMessage(const void * bufferPtr, size_t length);

  void RecvMessage(std::vector<char>& buffer);
  void RecvMessage(BinaryStream& buffer);

  void Connect(boost::asio::ip::tcp::endpoint& endpoint);
  void AsyncConnect(boost::asio::ip::tcp::endpoint endpoint, std::function<void()> callBack, int tryCount = 1);

  //void ListenAgain();

  //void WaitOnStop();

  size_t m_channel_idx;
  std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;

private:

  void DispatchSendMessage(std::shared_ptr<SendBuffer> buffer);
  void StartSend();

  void SendHandle(boost::system::error_code ec, size_t bytes_tranferred);
  void ConnectHandle(const boost::system::error_code & ec);



  std::list<std::shared_ptr<SendBuffer>> m_send_buffers;
  std::unique_ptr<boost::asio::io_service::work> m_Worker;
  boost::asio::strand m_send_strand;

  //std::mutex m_stop_mtx;
  //std::condition_variable m_stop_cond;
  //std::atomic<bool> m_stopped;

};



void ThreadPrint(std::string message);
template<typename T>
static std::string ToString(const T& t)
{
  return boost::lexical_cast<std::string>(t);
}


class NetworkManager
{
public:
  NetworkManager(std::string IP,
     int basePort,
     int maxThreadCount,
     bool initiate);

  ~NetworkManager();

  void MakeChannel();

  void Stop();
  bool Stopped();
  void Start();

  std::shared_ptr<Channel> mChannel;

private:

  std::atomic<bool> m_stopped;
  boost::asio::ip::tcp::endpoint mEndpoint;
  bool mInitator;
  int mMaxThreadCount;
  boost::asio::io_service m_io_service;
  std::vector<std::thread> m_threads;

};





#endif
