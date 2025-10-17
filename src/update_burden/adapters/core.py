import abc
from ..config import Settings

# from allocation.domain import model


class AbstractSourceCodeApiClient(abc.ABC):
    """
    Abstract client to communicate with source code repositories like GitHub    
    """
    @abc.abstractmethod
    def set_config(self, settings: Settings):
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, reference):
        raise NotImplementedError


class AbstractPackageRegistryApiClient(abc.ABC):
    """
    Abstract client to communicate with package registries like PyPi or NPM
    """
    @abc.abstractmethod
    def set_config(self, settings: Settings):
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, reference):
        raise NotImplementedError
