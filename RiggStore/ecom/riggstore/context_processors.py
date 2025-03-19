from .models import Cart  # Import your Cart model

def cart_context(request):
    cart_count = 0
    if request.user.is_authenticated:
        try:
            cart = Cart.objects.get(customer=request.user.customer)
            cart_count = cart.total_items()
        except Cart.DoesNotExist:
            pass
    return {'cart_item_count': cart_count}