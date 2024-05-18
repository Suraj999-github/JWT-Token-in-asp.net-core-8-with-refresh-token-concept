namespace JWT_DotNet_Core_8.Services
{
    public interface IAppSettingData
    {
        public string AppSettingValue(string RequestedData);
    }
    public class AppSettingData : IAppSettingData
    {
        private readonly IConfiguration _configuration;
        public AppSettingData(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string AppSettingValue(string RequestedData)
        {
            return (_configuration[RequestedData]);
        }
    }
}