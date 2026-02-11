namespace ModernWebGoat.Models;

public class Order
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public int ProductId { get; set; }

    // VULNERABILITY A04: No validation — negative quantity credits the user
    public int Quantity { get; set; }

    public decimal TotalPrice { get; set; }
    public DateTime OrderDate { get; set; } = DateTime.UtcNow;

    // VULNERABILITY A04: Coupon can be reused unlimited times
    public string? CouponCode { get; set; }
}
