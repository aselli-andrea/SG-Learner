"""Lettura continua del log di ovn-controller, come `tail -f`.

LogFollower restituisce a ogni chiamata solo le righe aggiunte al file dopo
l'ultima lettura. Tiene il file aperto, cosi' puo' continuare a leggerlo
anche se nel frattempo viene rinominato, e gestisce le situazioni tipiche
dei file di log:

- riga incompleta: se ovn-controller sta ancora scrivendo l'ultima riga,
  la parte gia' presente viene tenuta da parte e restituita completa al
  giro successivo;
- rotazione: logrotate rinomina il file (es. in .log.1) e ne crea uno
  nuovo, vuoto. Il follower continua a leggere il file vecchio e passa al
  nuovo solo quando il nuovo contiene dati. Cosi' non perde le ultime
  righe scritte nel file vecchio, e funziona anche quando ovn-controller
  non riapre il file e continua a scrivere in quello rinominato
  (situazione osservata dal vivo dopo un riavvio);
- troncamento: se il file diventa piu' corto della posizione letta, si
  riparte dall'inizio.

La posizione raggiunta (inode e offset) viene salvata nella tabella
`state` del Flow Store, cosi' dopo un riavvio del servizio la lettura
riprende da dove era arrivata, anche se nel frattempo il file e' stato
ruotato: il file con l'inode salvato viene cercato nella stessa cartella.
"""

import logging
import os

LOG = logging.getLogger(__name__)

_STATE_INODE = "ovn_log_inode"
_STATE_OFFSET = "ovn_log_offset"


def _inode(path):
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return None


def _size(path):
    try:
        return os.stat(path).st_size
    except FileNotFoundError:
        return 0


def _find_by_inode(path, inode):
    """Cerca nella cartella del log un file con l'inode dato (es. .log.1)."""
    folder = os.path.dirname(path) or "."
    base = os.path.basename(path)
    try:
        names = os.listdir(folder)
    except FileNotFoundError:
        return None
    for name in sorted(names):
        candidate = os.path.join(folder, name)
        if name.startswith(base) and _inode(candidate) == inode:
            return candidate
    return None


class LogFollower:
    """Legge le righe nuove di un file di log, riprendendo dopo un riavvio."""

    def __init__(self, path, store, start_at_end=True):
        """
        `start_at_end`: alla prima esecuzione (nessuna posizione salvata)
        parte dalla fine del file, ignorando le righe gia' presenti.
        """
        self.path = path
        self.store = store
        self._file = None
        self._inode = None
        self._offset = 0
        self._partial = b""
        self._restore(start_at_end)

    # --- Apertura e ripresa -------------------------------------------------

    def _open(self, path, offset):
        self.close()
        try:
            self._file = open(path, "rb")
        except FileNotFoundError:
            return False
        self._inode = os.fstat(self._file.fileno()).st_ino
        self._offset = offset
        self._file.seek(offset)
        self._partial = b""
        return True

    def _restore(self, start_at_end):
        inode = self.store.get_state(_STATE_INODE)
        offset = self.store.get_state(_STATE_OFFSET)
        if inode is not None and offset is not None:
            saved = _find_by_inode(self.path, int(inode))
            if saved and self._open(saved, int(offset)):
                LOG.info("Ripresa della lettura di %s dalla posizione %s",
                         saved, offset)
                return
            # Il file letto in precedenza non esiste piu': quello attuale
            # contiene solo righe successive, si legge dall'inizio
            if self._open(self.path, 0):
                LOG.info("File di log precedente non trovato: lettura di %s"
                         " dall'inizio", self.path)
            return
        if self._open(self.path, 0):
            if start_at_end:
                self._offset = os.fstat(self._file.fileno()).st_size
                self._file.seek(self._offset)
            LOG.info("Prima lettura di %s dalla posizione %d",
                     self.path, self._offset)

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None

    def _save(self):
        # La posizione salvata punta all'inizio dell'eventuale riga
        # incompleta, cosi' dopo un riavvio viene riletta per intero.
        self.store.set_state(_STATE_INODE, self._inode)
        self.store.set_state(_STATE_OFFSET, self._offset - len(self._partial))

    # --- Lettura ----------------------------------------------------------------

    def _read_available(self):
        """Legge tutto cio' che e' stato aggiunto al file aperto."""
        size = os.fstat(self._file.fileno()).st_size
        if size < self._offset:
            LOG.info("%s e' stato troncato: lettura dall'inizio", self.path)
            self._file.seek(0)
            self._offset, self._partial = 0, b""
        data = self._file.read()
        self._offset += len(data)
        return data

    def read_new_lines(self):
        """Restituisce la lista delle righe complete aggiunte al log."""
        if self._file is None and not self._open(self.path, 0):
            return []

        data = self._read_available()

        # Rotazione: il percorso indica un altro file. Si passa al nuovo
        # solo quando contiene dati; fino ad allora si resta sul vecchio.
        current = _inode(self.path)
        if current is not None and current != self._inode \
                and _size(self.path) > 0:
            LOG.info("%s e' stato ruotato: passaggio al nuovo file",
                     self.path)
            old = self._partial + data
            if old and not old.endswith(b"\n"):
                old += b"\n"    # l'ultima riga del file vecchio e' finita
            self._open(self.path, 0)
            data = old + self._read_available()
        else:
            data = self._partial + data

        *complete, self._partial = data.split(b"\n")
        if complete or data:
            self._save()
        return [line.decode("utf-8", errors="replace")
                for line in complete if line]
