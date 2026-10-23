"""Test della lettura continua del log (LogFollower) e del CollectionWorker."""

import os
import pathlib

import pytest

from sg_learner.follower import LogFollower
from sg_learner.service import CollectionWorker
from sg_learner.store import FlowStore

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "ovn_acl_log_sample.txt"


@pytest.fixture
def store(tmp_path):
    with FlowStore(tmp_path / "sg-learner.db") as s:
        yield s


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "ovn-controller.log"
    path.write_text("riga gia' presente\n")
    return path


def append(path, text):
    with open(path, "a") as f:
        f.write(text)


def test_first_run_starts_at_end_of_file(log, store):
    follower = LogFollower(str(log), store)

    assert follower.read_new_lines() == []
    append(log, "nuova 1\nnuova 2\n")
    assert follower.read_new_lines() == ["nuova 1", "nuova 2"]
    assert follower.read_new_lines() == []


def test_first_run_from_start_if_requested(log, store):
    follower = LogFollower(str(log), store, start_at_end=False)

    assert follower.read_new_lines() == ["riga gia' presente"]


def test_incomplete_line_is_returned_when_complete(log, store):
    follower = LogFollower(str(log), store)

    append(log, "riga a met")
    assert follower.read_new_lines() == []
    append(log, "a\n")
    assert follower.read_new_lines() == ["riga a meta"]


def test_resume_after_restart(log, store):
    first = LogFollower(str(log), store)
    append(log, "prima del riavvio\nincomplet")
    assert first.read_new_lines() == ["prima del riavvio"]

    # Il servizio si ferma; nel frattempo arrivano altre righe
    append(log, "a\ndurante il riavvio\n")

    second = LogFollower(str(log), store)
    assert second.read_new_lines() == ["incompleta", "durante il riavvio"]


def test_rotation_restarts_from_new_file(log, store):
    follower = LogFollower(str(log), store)
    append(log, "vecchio file\n")
    assert follower.read_new_lines() == ["vecchio file"]

    os.rename(log, str(log) + ".1")
    log.write_text("nuovo file\n")

    assert follower.read_new_lines() == ["nuovo file"]


def test_truncation_restarts_from_beginning(log, store):
    follower = LogFollower(str(log), store)
    append(log, "riga lunga che verra' cancellata\n")
    follower.read_new_lines()

    log.write_text("dopo\n")

    assert follower.read_new_lines() == ["dopo"]


def test_missing_file_is_not_an_error(tmp_path, store):
    path = tmp_path / "non-ancora-creato.log"
    follower = LogFollower(str(path), store)

    assert follower.read_new_lines() == []
    path.write_text("finalmente\n")
    assert follower.read_new_lines() == ["finalmente"]


def test_worker_saves_connections_from_the_log(log, store):
    worker = CollectionWorker(LogFollower(str(log), store), store)
    real_lines = FIXTURE.read_text()

    append(log, real_lines)
    saved = worker.poll()

    assert saved > 0
    assert store.total_connections() == saved
    assert worker.new_connections == saved

    # Le stesse righe non vengono lette due volte
    assert worker.poll() == 0
    worker.report()
    assert worker.new_connections == 0
