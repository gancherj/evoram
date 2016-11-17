#ifndef PROGRESSBAR_HPP
#define PROGRESSBAR_HPP

class ProgressBar
   {
      std::string mTaskName;
      int mStart, mEnd,mCur, mRange;
      size_t mExtra;
      bool mDone;

   public:

      ProgressBar(std::string task, int  start, int end, size_t extra = 0)
         : mTaskName(task),
         mStart(start),
         mEnd(end),
         mCur(-1),
         mExtra(extra),
         mDone(0)
      {
         mRange = (end - start);
         mRange = mRange ? mRange : 1;

         Update(start);
      }

      ~ProgressBar()
      {
         auto num = (mEnd - mStart) ? mEnd : 1;
         Update(num);
      }

      void Update( int newCur, size_t extraCur = 0)
      {
         //return;

         if (!mDone)
         {
            auto temp = (newCur - mStart) * 100 / mRange;

            if (temp != mCur)
            {
               mCur = temp;

               std::stringstream mBuffer;

               mBuffer << "\r";
               mBuffer << mTaskName << ": ";

               if (mCur < 10)
                  mBuffer << " ";
               if (mCur < 100)
                  mBuffer << " ";

               mBuffer << mCur << "%  [";

               auto bar = mCur / 10;
               for (int i = 0; i < bar; i++)
                  mBuffer << "#";

               for (int i = bar; i < 10; i++)
                  mBuffer << " ";

               mBuffer << "]";

               if (mExtra)
               {
                  mBuffer << " ( " << extraCur << " / " << mExtra << " )";
               }
               if (mCur == 100)
               {
                  mDone = true;
                  mBuffer << "\r";
               }

               std::cout << mBuffer.str();
            }
         }
      }

   };

#endif