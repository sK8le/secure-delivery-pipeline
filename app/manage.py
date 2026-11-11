"""Operator-only commands; no HTTP route exposes team assignment."""
import argparse
import json
import logging

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User

logger = logging.getLogger("vulntrack.operator")


def assign_team(db: Session, username: str, team: str) -> User:
    team = team.strip()
    if not team or len(team) > 64 or any(ord(char) < 32 or ord(char) == 127 for char in team):
        raise ValueError("Команда должна содержать от 1 до 64 символов без управляющих знаков")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise ValueError("Пользователь не найден")
    previous_team = user.team
    user.team = team
    db.commit()
    logger.warning(
        "Operator assigned user_id=%s from team=%r to team=%r",
        user.id, previous_team, team,
    )
    return user


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Управление командами VulnTrack")
    commands = parser.add_subparsers(dest="command", required=True)
    assign = commands.add_parser("assign-team", help="Назначить команду пользователю")
    assign.add_argument("--username", required=True)
    assign.add_argument("--team", required=True)
    commands.add_parser("list-users", help="Показать пользователей и их команды")
    args = parser.parse_args(argv)
    with SessionLocal() as db:
        if args.command == "list-users":
            for user in db.query(User).order_by(User.id):
                print(json.dumps({"id": user.id, "username": user.username, "team": user.team}, ensure_ascii=False))
            return
        try:
            user = assign_team(db, args.username, args.team)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps({"username": user.username, "team": user.team}, ensure_ascii=False))


if __name__ == "__main__":
    main()
