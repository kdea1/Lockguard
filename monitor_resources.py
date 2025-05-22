# monitor_resources.py
import psutil
import matplotlib.pyplot as plt

def monitor_system_resources():
    """Monitorea el uso de recursos del sistema"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    # Crear gráfica
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6, 4))
    ax1.bar(['CPU'], [cpu_percent], color='blue')
    ax1.set_ylim(0, 100)
    ax1.set_title('Uso de CPU (%)')
    
    ax2.bar(['Memoria'], [memory.percent], color='green')
    ax2.set_ylim(0, 100)
    ax2.set_title('Uso de Memoria (%)')
    
    plt.tight_layout()
    return fig
