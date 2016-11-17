#include "NetworkManager.hpp"

#include <mutex>
#include <iostream>
#include <atomic>
#include <chrono>
#include <sstream>

#ifdef MSVS

#include <windows.h>
   const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
   typedef struct tagTHREADNAME_INFO
   {
      DWORD dwType; // Must be 0x1000.
      LPCSTR szName; // Pointer to name (in user addr space).
      DWORD dwThreadID; // Thread ID (-1=caller thread).
      DWORD dwFlags; // Reserved for future use, must be zero.
   } THREADNAME_INFO;
#pragma pack(pop)

   void SetThreadName(const char* threadName, DWORD dwThreadID)
   {
      THREADNAME_INFO info;
      info.dwType = 0x1000;
      info.szName = threadName;
      info.dwThreadID = dwThreadID;
      info.dwFlags = 0;

      __try
      {
         RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
      }
   }
#else
   void SetThreadName(const char* threadName, int dwThreadID)
   {

   }
#endif

   std::mutex global_stream_lock;

   void ThreadPrint(std::string message)
   {

      std::stringstream ss;
      auto id = std::this_thread::get_id();

      ss << "[" << id << "] " << message;

      //std::unique_lock<std::mutex> lg(global_stream_lock);

      global_stream_lock.lock();
      std::cout << ss.str() << std::endl;
      global_stream_lock.unlock();
   }


   NetworkManager::NetworkManager(std::string IP,
      int basePort,
      int maxThreadCount,
      bool initiate)
      :mMaxThreadCount(maxThreadCount),
      mInitator(initiate),
      m_stopped(false)
   {
      boost::asio::io_service::work m_Worker(m_io_service);
      boost::asio::ip::tcp::resolver resolver(m_io_service);
      boost::asio::ip::tcp::resolver::query query(IP,
         boost::lexical_cast<std::string>(basePort));

      mEndpoint = *resolver.resolve(query);

      MakeChannel();
   }

   void NetworkManager::MakeChannel()
   {


      boost::asio::io_service::work work(m_io_service);

      try {
      m_threads.emplace_back([this]() {
            //ThreadPrint("Thread Started");
            // Worker thread loop

            std::string threadName;

            if (mInitator)
               threadName = "Client Channel Thread ";
            else
               threadName = "Server Channel Thread ";

            SET_THREAD_NAME(threadName.c_str());
            while (true)
            {
               try
               {
                  boost::system::error_code ec;
                  m_io_service.run(ec);
                  if (ec)
                  {
                     ThreadPrint(std::string{ " Error: " } +ec.message());
                  }
                  break;
               }
               catch (std::exception & ex)
               {
                  ThreadPrint(std::string{ " Error: " } +ex.what());
               }
            }
            // end of worker thread loop
            //ThreadPrint("Thread Finish");
         });
      }
      catch (std::exception& ex)
      {
         std::cout<<ex.what()<<std::endl;
      }
      if (mInitator)
      {


            std::unique_ptr<boost::asio::ip::tcp::socket> socket(new boost::asio::ip::tcp::socket(m_io_service));

            mChannel.reset(new Channel(m_io_service, 0, std::move(socket)));


         std::atomic<bool> cnnct;
         cnnct = false;



         mChannel->AsyncConnect(mEndpoint, [&]()
         {
         //ThreadPrint("Init send - " + ToString(chnnl->m_channel_idx));

               auto buffer = boost::asio::buffer(&((mChannel)->m_channel_idx), sizeof(size_t));
               boost::asio::write(*((mChannel)->m_socket), buffer);
               cnnct = true;
         }, 1000);


          while (cnnct == false)
         {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
         }
         cnnct = false;
      }
      else
      {
         boost::system::error_code ec;

            mChannel.reset(new Channel(m_io_service, 0, std::move(std::unique_ptr<boost::asio::ip::tcp::socket>())));


         std::unique_ptr<boost::asio::ip::tcp::socket> unInitSocket;

         boost::asio::ip::tcp::acceptor acceptor(m_io_service);
         acceptor.open(mEndpoint.protocol());
         acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
         acceptor.bind(mEndpoint, ec);
         if (ec)ThreadPrint("Bind error: " + ec.message());
         acceptor.listen(boost::asio::socket_base::max_connections);


         std::atomic<bool> cnnct;
         cnnct = false;


            unInitSocket.reset(new boost::asio::ip::tcp::socket(m_io_service));
            std::unique_ptr<boost::asio::ip::tcp::socket>& sckt = unInitSocket;

            //ThreadPrint("waiting for accept");

            acceptor.async_accept(*sckt,
               [&](const boost::system::error_code & ec)
            {
               if (ec)
               {
                  ThreadPrint("Error with accept : " + ec.message());
                  assert(0);
               }
               else
               {
                  size_t channelIdx = size_t (- 1);

                  boost::asio::ip::tcp::socket& ss = *sckt;
                  auto buffer = boost::asio::buffer(&channelIdx, sizeof(size_t));

                  boost::asio::read(ss, buffer);

                  ThreadPrint("channel " + ToString(channelIdx) + " accept");

                  assert(this->mChannel->m_socket == nullptr);

                  this->mChannel->m_socket.reset(sckt.release());
                  cnnct = true;
               }
               //this->AccecptHandle(ec);
               //callBack();
            });

            while (cnnct == false) {
               // Sleep(10);
               // assumming the VS Sleep takes in ms
               std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            cnnct = false;
      }
   }

   //void NetworkManager::AcceptNewConnection(Channel* channel)
   //{
   //   boost::system::error_code ec;

   //   boost::asio::ip::tcp::acceptor acceptor(m_io_service);
   //   acceptor.open(mEndpoint.protocol());
   //   acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
   //   acceptor.bind(mEndpoint, ec);
   //   if (ec)ThreadPrint("Bind error: " + ec.message());
   //   acceptor.listen(boost::asio::socket_base::max_connections);

   //   channel->m_socket.reset(new boost::asio::ip::tcp::socket(m_io_service));


   //   acceptor.accept(*channel->m_socket.get(),ec);

   //   if (ec)ThreadPrint("Accept error: " + ec.message());
   //}


   NetworkManager::~NetworkManager()
   {
      // delete the channel first less we get an error with them using the destroyed io_service.
      mChannel = nullptr;
   }

   void NetworkManager::Stop()
   {
      //for (auto& channel : mChannels)
      //   channel->Stop();

      m_io_service.run();
      m_io_service.stop();
      m_stopped = true;

      m_threads[0].join();
   }

   bool NetworkManager::Stopped()
   {
      return m_stopped;
   }
   void NetworkManager::Start()
   {
      if (m_stopped)
      {
         m_io_service.reset();
      }
   }


   Channel::Channel(boost::asio::io_service& io_service,
      size_t channelIdx,
      std::unique_ptr<boost::asio::ip::tcp::socket> socket)
      : m_channel_idx(channelIdx),
      m_socket(std::move(socket)),
      m_send_strand(io_service),
      m_Worker(new boost::asio::io_service::work(io_service)),
      m_send_buffers()
   {}

   Channel::~Channel()
   {}

   void Channel::AsyncConnect(boost::asio::ip::tcp::endpoint endpoint, std::function<void()> callBack, int tryCount)
   {
      ThreadPrint("Waiting for connect");
      m_socket->async_connect(endpoint,
         [this, callBack, tryCount, endpoint](const boost::system::error_code & ec)
      {
         if (ec)
         {
            // Sleep(100);
            // assumming the VS Sleep takes in ms
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            AsyncConnect(endpoint, callBack, tryCount - 1);
         }
         else
         {
            this->ConnectHandle(ec);

            ThreadPrint("connected");
            callBack();

         }
      });
   }

   void Channel::Connect(boost::asio::ip::tcp::endpoint& endpoint)
   {
      //ThreadPrint("Waiting for connect");
      m_socket->connect(endpoint);

      //ThreadPrint("channel " + ToString(m_channel_idx) + " Connected");
   }

   void Channel::RecvMessage(std::vector<char>& buffer)
   {
      // not used

      // dont use anything but the socket
      assert(buffer.size() == 0);

      uint32_t size;
      std::mutex mtx;
      std::lock_guard<std::mutex> lock(mtx);

      auto readSize0 = boost::asio::read(*m_socket, boost::asio::buffer(&size, sizeof(uint32_t)));

      assert(readSize0 == sizeof(uint32_t));

      buffer.resize(buffer.size() + size, char(0));

      //std::vector<char>::iterator start = buffer.end() - size;
      auto asioBuffer = boost::asio::buffer(buffer.data(), size);

      boost::asio::read(*m_socket, asioBuffer);
   }

   void Channel::RecvMessage(BinaryStream& buffer)
   {
      // std::cout << "Channel::RecvMessage" << std::endl;

      // Concurrent space, not thread safe!!!
      // dont use anything but the socket
      assert(!buffer.size());

      uint32_t size;

      std::mutex mtx;
      std::lock_guard<std::mutex> lock(mtx);

      auto readSize0 = boost::asio::read(*m_socket, boost::asio::buffer(&size, sizeof(uint32_t)));


      assert(readSize0 == sizeof(uint32_t));

      buffer.Reserve(size);

      // boost::asio::buffer return a buffer

      auto asioBuffer = boost::asio::buffer(buffer.HeadP(), size);
      auto readSize = boost::asio::read(*m_socket, asioBuffer);
      assert(readSize == size);
      // buffer.SeekP(buffer.TellP() + size);
      buffer.SeekP(size);
   }

   void Channel::AsyncSendMessageCopy(const void * bufferPtr, size_t length)
   {
      assert(length < INT32_MAX);

      //std::cout << "sending " << length << "byte" << std::endl;
      std::shared_ptr<SendBuffer> buf(new SendBuffer);

      buf->optVectPtr.reset(new std::vector<char>(reinterpret_cast<const char*>(bufferPtr), reinterpret_cast<const char*>(bufferPtr)+length));
      buf->data = buf->optVectPtr->data();
      buf->size = static_cast<uint32_t>(buf->optVectPtr->size());


      m_send_strand.post([this, buf]() {
         // Strand space, single threaded here.
         this->DispatchSendMessage(buf);
      });
   }
   void Channel::AsyncSendMessage(const void * bufferPtr, size_t length)
   {
      assert(length < INT32_MAX);

      //std::cout << "sending " << length << "byte" << std::endl;
      std::shared_ptr<SendBuffer> buf(new SendBuffer);


      buf->data = bufferPtr;
      buf->size = static_cast<uint32_t>(length);

      m_send_strand.post([this, buf]() {
         // Strand space, single threaded here.
         this->DispatchSendMessage(buf);
      });
   }
   void Channel::SendMessage(const void * bufferPtr, size_t length)
   {
      assert(length < INT32_MAX);

      std::shared_ptr<SendBuffer> buf(new SendBuffer);

      buf->data = bufferPtr;
      buf->size = static_cast<uint32_t>(length);

      std::mutex mtx;
      std::condition_variable cond;
      std::unique_lock<std::mutex> lock(mtx);

      buf->cond = &cond;
      buf->mtx = &mtx;

      m_send_strand.post([this, buf]() {
         // Strand space, single threaded here.
         this->DispatchSendMessage(buf);
      });

      cond.wait(lock);
   }

   void Channel::AsyncSendMessage(std::unique_ptr<std::vector<char>> buffer)
   {
      //std::cout << "sending " << buffer->size() << "byte" << std::endl;
      std::shared_ptr<SendBuffer> buf(new SendBuffer);

      buf->optVectPtr.reset(buffer.release());
      buf->data = buf->optVectPtr->data();
      buf->size = buf->optVectPtr->size();

      assert(buf->size < INT32_MAX);
      m_send_strand.post([this, buf]() {
         // Strand space, single threaded here.
         this->DispatchSendMessage(buf);
      });
   }

   void Channel::AsyncSendMessage(std::unique_ptr<BinaryStream> buffer)
   {
      //std::cout << "sending " << buffer->size() << "byte" << std::endl;
      std::shared_ptr<SendBuffer> buf(new SendBuffer);

      buf->optBinStrPtr.reset(buffer.release());
      buf->data = buf->optBinStrPtr->HeadG();
      buf->size = buf->optBinStrPtr->size();

      assert(buf->size < INT32_MAX);
      //assert();

      m_send_strand.post([this, buf]() {
         // Strand space, single threaded here.
         this->DispatchSendMessage(buf);
      });

   }

   void Channel::Stop()
   {
      m_Worker.reset();

      boost::system::error_code ec;
      m_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

      //std::unique_lock<std::mutex> lock(m_stop_mtx);

      //m_stopped = true;
      //m_stop_cond.notify_all();
   }


   //void Channel::WaitOnStop()
   //{
   //   std::unique_lock<std::mutex> lock(m_stop_mtx);

   //   while (m_stopped == false)
   //   {
   //      m_stop_cond.wait(lock);
   //   }
   //}

   void Channel::DispatchSendMessage(std::shared_ptr<SendBuffer> buffer)
   {
      // Strand space, single threaded here.

      bool should_start_send = m_send_buffers.empty();
      m_send_buffers.push_back(buffer);

      if (should_start_send)
      {
         StartSend();
      }
   }

   void Channel::StartSend()
   {
      // Strand space, single threaded here.
      if (!m_send_buffers.empty())
      {


         std::array < boost::asio::const_buffer, 2 > buff = {
            boost::asio::buffer(&m_send_buffers.front()->size, sizeof(int32_t)),
            boost::asio::buffer(m_send_buffers.front()->data, m_send_buffers.front()->size)
         };
         auto This = shared_from_this();

         boost::asio::async_write(*m_socket,
            buff,
            m_send_strand.wrap([This](boost::system::error_code ec, size_t bytes_tranferred)
         {

            if (ec)
            {
               std::cout << "write error: " << ec.message() << std::endl;

            }
            auto& front = This->m_send_buffers.front();
            // Strand space, single threaded here.
            assert(bytes_tranferred == front->size + sizeof(int32_t));

            if (front->mtx != nullptr)
            {
                  front->mtx->lock(); // make sure that the sender has waited on cond
                  front->mtx->unlock();

                  front->cond->notify_one(); // wake him up.
            }

            This->m_send_buffers.pop_front();

            This->SendHandle(ec, bytes_tranferred);
         }));

         // No longer thread safe!!!
      }
   }

   void Channel::SendHandle(boost::system::error_code ec, size_t bytes_tranferred)
   {
      // Strand space, single threaded here.

      if (ec)
      {
         ThreadPrint("Error with sending in channel " + ToString(m_channel_idx) + " : " + ec.message());
      }
      else
      {
         StartSend();
      }
   }

   //void Channel::AccecptHandle(const boost::system::error_code & ec)
   //{
   //   if (ec)
   //   {
   //      ThreadPrint("Error with accept in channel " + ToString(m_channel_idx) + " : " + ec.message());
   //   }
   //   else
   //   {
   //      ThreadPrint("channel " + ToString(m_channel_idx) + " accept");
   //   }
   //}



   void Channel::ConnectHandle(const boost::system::error_code & ec)
   {
      if (ec)
      {
         ThreadPrint("Error with connect in channel " + ToString(m_channel_idx) + " : " + ec.message());
      }
      else
      {
         //ThreadPrint("channel " + ToString(m_channel_idx) + " Connected");

      }
      //Recv();
   }
