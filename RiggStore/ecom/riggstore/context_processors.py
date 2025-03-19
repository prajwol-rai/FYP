from django.core.cache import cache
from .models import Cart

def cart_context(request):
    if not request.user.is_authenticated:
        return {'cart_item_count': 0}
    
    cache_key = f'cart_count_{request.user.id}'
    cart_count = cache.get(cache_key)
    
    if cart_count is None:
        try:
            cart = Cart.objects.prefetch_related('items').get(
                customer=request.user.customer
            )
            cart_count = cart.total_items()
            cache.set(cache_key, cart_count, 300)  # Cache for 5 minutes
        except Cart.DoesNotExist:
            cart_count = 0
    
    return {'cart_item_count': cart_count}