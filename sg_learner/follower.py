"""Lettura continua del log di ovn-controller, come `tail -f`.

LogFollower restituisce a ogni chiamata solo le righe aggiunte al file dopo
l'ultima lettura, e gestisce tre situazioni tipiche dei file di log:

- riga incompleta: se ovn-controller sta ancora scrivendo l'ultima riga,
  la parte gia' presente viene tenuta da parte e restituita completa al
  giro successivo;
- rotazione: logrotate rinomina il file e ne crea uno nuovo (inode
  diverso), quindi si riparte dall'inizio del nuovo file;
- troncamento: se il file diventa piu' corto della posizione letta, si
  riparte dall'inizio.

La posizione raggiunta (inode e offset) viene salvata nella tabella
`state` del Flow Store, cosi' dopo un riavvio del servizio la lettura
riprende da dove era arrivata, senza perdere ne' rileggere righe.
"""

import logging
import os

LOG = logging.getLogger(__name__)

_STATE_INODE = "ovn_log_inode"
_STATE_OFFSET = "ovn_log_offset"


class LogFollower:
    """Legge le righe nuove di un file di log, riprendendo dopo un riavvio."""

    def __init__(self, path, store, start_at_end=True):
        """
        `start_at_end`: alla prima esecuzione (nessuna posizione salvata)
        parte dalla fine del file, ignorando le righe gia' presenti.
        """
        self.path = path
        self.store = store
        self._inode = None
        self._offset = 0
        self._partial = b""
        self._restore(start_at_end)

    def _restore(self, start_at_end):
        inode = self.store.get_state(_STATE_INODE)
        offset = self.store.get_state(_STATE_OFFSET)
        if inode is not None and offset is not None:
            self._inode, self._offset = int(inode), int(offset)
            LOG.info("Ripresa della lettura di %s dalla posizione %d",
                     self.path, self._offset)
            return
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        self._inode = st.st_ino
        self._offset = st.st_size if start_at_end else 0
        LOG.info("Prima lettura di %s dalla posizione %d",
                 self.path, self._offset)

    def _save(self, offset):
        self.store.set_state(_STATE_INODE, self._inode)
        self.store.set_state(_STATE_OFFSET, offset)

    def read_new_lines(self):
        """Restituisce la lista delle righe complete aggiunte al file."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []

        if self._inode != st.st_ino:
            if self._inode is not None:
                LOG.info("%s e' stato ruotato: lettura dall'inizio",
                         self.path)
            self._inode, self._offset, self._partial = st.st_ino, 0, b""
        elif st.st_size < self._offset:
            LOG.info("%s e' stato troncato: lettura dall'inizio", self.path)
            self._offset, self._partial = 0, b""

        if st.st_size == self._offset:
            return []

        with open(self.path, "rb") as f:
            f.seek(self._offset)
            data = f.read()
        self._offset += len(data)

        data = self._partial + data
        *complete, self._partial = data.split(b"\n")
        # La posizione salvata punta all'inizio della riga incompleta,
        # cosi' dopo un riavvio viene riletta per intero.
        self._save(self._offset - len(self._partial))

        return [line.decode("utf-8", errors="replace") for line in complete]
