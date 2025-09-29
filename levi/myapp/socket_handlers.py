import socketio
from django.contrib.auth import get_user_model
from .models import Message
from asgiref.sync import sync_to_async






#— Add chat events (one-one chat: user ↔ admin)


User = get_user_model()

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")

# Store connected users (i.e users that are online) {user_id: sid}
connected_users = {}

@sio.event
async def connect(sid, environ, auth):
    print("Client connected:", sid)
    user_id = auth.get("user_id") if auth else None
    if user_id:
        connected_users[user_id] = sid
        print(f"User {user_id} is online")

@sio.event
async def disconnect(sid):
    print("Client disconnected:", sid)
    for uid, stored_sid in list(connected_users.items()):
        if stored_sid == sid:
            del connected_users[uid]
            print(f"User {uid} went offline")



@sio.event
async def send_message(sid, data):
    """
    data = {
      "sender_id": 1,
      "receiver_id": 2,
      "content": "Hello Admin Fazola!"
      "type": "text"
      "is_read": false
    }
    """
    sender_id = data["sender_id"]
    recipient_id = data["receiver_id"]
    message = data["content"]
    type = data["type"]
    is_read = data["is_read"]

    # Fetch sender and recipient users
    sender = await sync_to_async(User.objects.get)(id=sender_id)
    receiver = await sync_to_async(User.objects.get)(id=recipient_id)

    # Save the message
    msg = await sync_to_async(Message.objects.create)(
        sender=sender,
        receiver=receiver,
        content=message,
        type=type,
        is_read=is_read,
    )

    # Build payload including user data
    payload = {
        "id": msg.id,
        "content": msg.content,
        "type": msg.type,
        "is_read": msg.is_read,
        "created_at": msg.timestamp.isoformat(),
        "sender": {
            "id": sender.id,
            "first_name": sender.first_name,
            "last_name": sender.last_name,
            "email": sender.email,
        },
        "receiver": {
            "id": receiver.id,
            "first_name": receiver.first_name,
            "last_name": receiver.last_name,
            "email": receiver.email,
        },
    }

    # Deliver to recipient if online
    recipient_sid = connected_users.get(str(recipient_id))
    if recipient_sid:
        await sio.emit("receive_message", payload, to=recipient_sid)

    # Echo back to sender too
    await sio.emit("receive_message", payload, to=sid)


