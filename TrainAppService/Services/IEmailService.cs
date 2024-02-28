using TrainAppService.Dtos;

namespace TrainAppService.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}