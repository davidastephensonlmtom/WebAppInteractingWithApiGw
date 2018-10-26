using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WebAppInteractingWithApiGw.Cache
{
    public class NaiveSessionCache : TokenCache
    {
        private static readonly object FileLock = new object();
        string UserObjectId = string.Empty;
        string CacheId = string.Empty;
        ISession Session = null;

        public NaiveSessionCache(string userId, ISession session)
        {
            UserObjectId = userId;
            CacheId = UserObjectId + "_TokenCache";
            Session = session;
            AfterAccess = AfterAccessNotification;
            BeforeAccess = BeforeAccessNotification;
            Load();
        }

        public void Load()
        {
            lock (FileLock)
            {
                Deserialize(Session.Get(CacheId));
            }
        }

        public void Persist()
        {
            lock (FileLock)
            {
                var byteArray = Serialize();
                var str = System.Text.Encoding.UTF8.GetString(byteArray);
                // reflect changes in the persistent store
                Session.Set(CacheId, byteArray);
                // once the write operation took place, restore the HasStateChanged bit to false
                HasStateChanged = false;
            }
        }

        // Empties the persistent store.
        public override void Clear()
        {
            base.Clear();
            Session.Remove(CacheId);
        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
            Persist();
        }

        // Triggered right before ADAL needs to access the cache.
        // Reload the cache from the persistent store in case it changed since the last access.
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            Load();
        }

        // Triggered right after ADAL accessed the cache.
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (HasStateChanged)
            {
                Persist();
            }
        }
    }
}
