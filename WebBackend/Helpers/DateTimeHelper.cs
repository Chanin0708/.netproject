using System;

namespace WebBackend.Helpers
{
    public static class DateTimeHelper
    {
        // Method to get the current date and time in UTC+7 (Bangkok time)
        public static DateTime GetBangkokTime()
        {
            TimeZoneInfo bangkokTimeZone = TimeZoneInfo.FindSystemTimeZoneById("SE Asia Standard Time");
            DateTime bangkokTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, bangkokTimeZone);
            return bangkokTime;
        }
    }
}
