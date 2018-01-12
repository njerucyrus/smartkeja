from smarthouse.models import Agent, HouseOwner, House


def get_account_type(request):
    account_type = ''
    phone_number = ''
    context = dict({})
    try:
        if request.user.is_authenticated:
            agent_exists = Agent.objects.filter(user=request.user)[:1].exists()
            if agent_exists:
                account_type = 'agent'
                agent = Agent.objects.get(user=request.user)
                phone_number = agent.phone_number
            if request.user.is_staff:
                account_type = "owner"
                house_owner = HouseOwner.objects.get(user=request.user)
                phone_number = house_owner.phone_number

            if not request.user.is_staff and not agent_exists:
                account_type = "client"

    except (Agent.DoesNotExist, HouseOwner.DoesNotExist):
        pass
    context['account_type'] = account_type
    context['phone_number'] = phone_number
    return context


def get_house_posts(request):
    context = dict({})
    houses = House.objects.all()
    context['house_options'] = houses
    return context





