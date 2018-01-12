import json

from django.http import HttpResponse

from smarthouse.models import House


def list_houses(request):
    houses = House.objects.filter(is_available=True, on_sale=False)[:10]
    house_list = []
    for house in houses:
        item = "House at {} For Ksh {}".format(str(house.location), str(house.rent_price))
        house_list.append(item)

    return HttpResponse(json.dumps({"data": house_list}), content_type="application/json")


def search_house(request, location=None):
    houses = House.objects.filter(is_available=True, on_sale=False, location__icontains=location)
    house_list = []
    for house in houses:
        item = "House at {} For Ksh {}".format(str(house.location), str(house.rent_price))
        house_list.append(item)

    return HttpResponse(json.dumps({"data": house_list}), content_type="application/json")

