#ifndef SHARED_BUFFER_H
#define SHARED_BUFFER_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#define SHM_NAME "/fw_shm_buffer"
#define MAX_PACKETS 4096
#define PACKET_SIZE 40

/* структура слота для пакета */
typedef struct {
	uint8_t data[PACKET_SIZE]; //сырые данные псевдо-IP пакета
	struct timespec timestamp; //время генерации (для замера Latency)
	uint32_t seq_num;          //порядковый номер для контроля потерь/дубликатов
	volatile uint8_t is_ready; //флаг готовности для lock-free (0 - пусто/в процессе, 1 - готово к чтению)
} packet_slot_t;

/* 2. Управляющий заголовок и буфер */
typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond_new_packet;
	pthread_cond_t cond_free_space;

	alignas(64) volatile size_t head; //отсюда читает сервер (multi-consumer)
	alignas(64) volatile size_t tail; //сюда пишет клиент (Multi-Producer)

	/* Статистика и мониторинг */
	alignas(64) volatile uint64_t total_generated; //Всего создано клиентом
	volatile uint64_t total_processed; //Всего проверено сервером
	volatile uint64_t total_dropped; //Сброшено из-за переполнения буфера

	/* Сам пул пакетов*/
	packet_slot_t slots[MAX_PACKETS];
} shared_ring_buffer_t;

#endif