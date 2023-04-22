/*
original source from: https://github.com/harshvs/LRUCache/blob/master/LRUCache.h
MIT License

Copyright (c) 2017 Harsh Vardhan Singh
Portions Copyright (c) 2022 Michael Toutonghi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef LRUCACHE_H
#define LRUCACHE_H

#include <iterator>
#include <list>
#include <map>

#include "sync.h"
#include "util.h"

template <typename TKey, typename TValue>
class LRUCache {
private:
    class _LRUEntry {
    public:
        _LRUEntry(const TKey &key, const TValue &value) : Key(key), Value(value) { }

        TKey Key;
        TValue Value;
    };

    class _LookUpEntry {
    public:
        typename std::list<_LRUEntry>::iterator LRUEntryRef;
    };

    // Cache store cum LRU tracker
    std::list<_LRUEntry> m_lruList;
    std::map<TKey, _LookUpEntry> m_lookUpMap;

    int m_capacity;
    float m_compactFactor;
    bool m_threadSafe;

    static constexpr const float DEFAULT_COMPACT_FACTOR = 0.1;
    static constexpr const int DEFAULT_CAPACITY = 1000;

    CCriticalSection m_cacheLock;

public:
    LRUCache(int capacity=DEFAULT_CAPACITY, float compactionFactor=DEFAULT_COMPACT_FACTOR, bool ThreadSafe=false) :
        m_capacity(capacity), m_compactFactor(compactionFactor), m_threadSafe(ThreadSafe) {}

    int count(const TKey &key)
    {
        if (m_threadSafe)
        {
            LOCK(m_cacheLock);
            return m_lookUpMap.count(key);
        }
        else
        {
            return m_lookUpMap.count(key);
        }
    }

    TValue Get(const TKey &key)
    {
        if (m_threadSafe)
        {
            LOCK(m_cacheLock);
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end())
            {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin())
                {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // return the copy
                return lruEntry->Value;
            } else {
                return TValue();
            }
        }
        else
        {
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end())
            {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin())
                {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // return the copy
                return lruEntry->Value;
            } else {
                return TValue();
            }
        }
    }

    bool Get(const TKey &key, TValue &outValue)
    {
        if (m_threadSafe)
        {
            LOCK(m_cacheLock);
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end()) {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin())
                {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // copy the value
                outValue = lruEntry->Value;
                return true;
            } else {
                return false;
            }
        }
        else
        {
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end()) {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin())
                {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // copy the value
                outValue = lruEntry->Value;
                return true;
            } else {
                return false;
            }
        }
    }

    void Put(const TKey &key, const TValue &value)
    {
        if (m_threadSafe)
        {
            LOCK(m_cacheLock);
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end()) {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin()) {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // copy the new value
                lruEntry->Value = value;
            } else {
                m_lruList.emplace_front(_LRUEntry(key, value));
                m_lookUpMap[key] = _LookUpEntry{m_lruList.begin()};
            }
            ensureCompaction();
        }
        else
        {
            auto mapEntry = m_lookUpMap.find(key);
            if (mapEntry != m_lookUpMap.end()) {
                auto lruEntry = (mapEntry->second).LRUEntryRef;
                // move the item to front.
                if (lruEntry != m_lruList.begin()) {
                    m_lruList.splice(m_lruList.begin(), m_lruList, lruEntry, std::next(lruEntry));
                }
                // copy the new value
                lruEntry->Value = value;
            } else {
                m_lruList.emplace_front(_LRUEntry(key, value));
                m_lookUpMap[key] = _LookUpEntry{m_lruList.begin()};
            }
            ensureCompaction();
        }
    }

private:
    void ensureCompaction()
    {
        int cacheOrigSize = m_lruList.size();
        if (cacheOrigSize < m_capacity) {
            return;
        }
        int cutPosition = m_capacity * (1 - m_compactFactor);
        Log("Evicting Cache, at capacity:" + std::to_string(cacheOrigSize) + "; Cut at:" + std::to_string(cutPosition));
        // Remove entries from the look-up map
        auto lruIter = m_lruList.begin();
        for (std::advance(lruIter, cutPosition); lruIter != m_lruList.end(); lruIter++)
        {
            m_lookUpMap.erase(lruIter->Key);
        }
        // Trim the LRU list
        {
            auto lruIter = m_lruList.begin();
            std::advance(lruIter, cutPosition);
            m_lruList.erase(lruIter, m_lruList.end());
        }
        Log("Cache trimmed to:" + std::to_string(m_lruList.size()));
    }

    void Log(const std::string &msg) {
        LogPrint("lrucache", "%s\n", msg.c_str());
    }
};

#endif // LRUCACHE_H
